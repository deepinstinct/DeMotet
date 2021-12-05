#include "EmotetUnpacker.h"

void HandleFile(const wstring& FilePath, const wstring& OutputFolder)
{
    // get the filename from the complete path
    const wstring baseName = FilePath.substr(FilePath.find_last_of(L'\\') + 1);

    // print the left column of the csv report
    wcout << baseName << ",";

    // read and validate the file. If it is invalid an exception will be thrown
    PeFile* pe = nullptr;
    try
    {
	    pe = new PeFile(FilePath);
    }
    catch (exception& ex)
    {
        wcout << ex.what() << endl;
        return;
    }
    bool payloadDecrypted = false;
    vector<uint8_t> encryptedDataVector;
    for (const auto& [extractionPointer, DecryptionPointer] : g_PairVector)
    {
        encryptedDataVector.clear();
        if (!extractionPointer->Extract(pe, encryptedDataVector))
            continue;
        if (DecryptionPointer->Decrypt(encryptedDataVector.data(), encryptedDataVector.size()))
        {
            payloadDecrypted = true;
            break;
        }
    }
    delete pe;
    if (payloadDecrypted)
    {
        // verify that the decrypted data is a valid PE file
        try
        {
            PeFile decryptedPe(encryptedDataVector);
        }
        catch (exception& ex)
        {
            wcout << "payload is an invalid PE. " << ex.what() << endl;
            return;
        }

        // if the path for the payload is invalid, an exception will be thrown
        try
        {
            WritePayloadToDisk(baseName, OutputFolder, encryptedDataVector);
            wcout << L"success" << endl;
        }
        catch (exception& ex)
        {
            wcout << ex.what() << endl;
        }
    }
    else
    {
        wcout << L"unknown variant" << endl;
    }
}

void IterateFolder(const wstring& FolderPath, const wstring& OutputFolder)
{
    // Iterating a folder that doesn't exist will cause an exception
    try
    {
        for (auto& directoryEntry : recursive_directory_iterator(FolderPath))
        {
            if (directoryEntry.is_regular_file())
                HandleFile(directoryEntry.path(), OutputFolder);
        }
    }
    catch (exception& ex)
    {
        wcout << ex.what() << endl;
    }
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    // get command line values
    wstring outputFolder;
    if (1 == argc)
    {
        wcout << L"usage: emotet_unpacker.exe EMOTET_LOADERS_DIR [PAYLOADS_DIR]" << endl;
        return EXIT_FAILURE;
    }
    if (3 == argc)
    {
        outputFolder.assign(argv[2]);
        // if the folder above the OutputFolder doesn't exist, an exception will be raised
        try
        {
            CreateOutputFolder(outputFolder);
        }
        catch (exception& ex)
        {
            wcout << ex.what();
            return EXIT_FAILURE;
        }
    }

    const wstring loadersDir = argv[1];

    // print columns of the csv report
    wcout << L"hash,result" << endl;

    // each variant stores the encrypted data in a different place and uses a different decryption algorithms
	// the vector contains pairs of methods to locate and decrypt the data
    g_PairVector.emplace_back(new DataSectionExtraction, new DataSectionDecryption);
    g_PairVector.emplace_back(new ResourceExtraction, new ResourceDecryption);
    IterateFolder(loadersDir, outputFolder);

    // delete the dynamic allocations in the vector
    for (const auto& [extractionPointer, DecryptionPointer] : g_PairVector)
    {
        delete extractionPointer;
        delete DecryptionPointer;
    }
    return EXIT_SUCCESS;
}
