#include "EmotetUnpacker.h"

void DecryptResource(const PBYTE Buffer, const DWORD ResourceSize, const unsigned char* Key, const DWORD KeySize)
{
    XorDecryption(Buffer, ResourceSize, Key, KeySize);
}

void ExtractPayload(const HMODULE ModuleHandle, const wstring& Filename, const wstring& OutputFolder)
{
    // find encrypted resource
    ResourceInfo encryptedResourceInfo = {};
    const bool resourceFound = FindEncryptedResource(ModuleHandle, &encryptedResourceInfo);
    if (!resourceFound)
    {
        wcout << "no encrypted resource found" << endl;
        return;
    }
    
    const PBYTE resourceAddress = encryptedResourceInfo.ResourceAddress + ENCRYPTED_DATA_OFFSET;
    const DWORD resourceSize = encryptedResourceInfo.ResourceSize - ENCRYPTED_DATA_OFFSET;

    const auto payloadBuffer = static_cast<PBYTE>(VirtualAlloc(nullptr, resourceSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (nullptr == payloadBuffer)
    {
        wcout << "failed to allocate memory" << endl;
        return;
    }

    bool payloadDecrypted = false;
    for (const auto& [key, keySize] : g_XorKeys)
    {
        memcpy_s(payloadBuffer, resourceSize, resourceAddress, resourceSize);
        DecryptResource(payloadBuffer, resourceSize, key, keySize);
        const WORD dosMagic = *reinterpret_cast<PWORD>(payloadBuffer);
        if (IMAGE_DOS_SIGNATURE == dosMagic)
        {
            payloadDecrypted = true;
            break;
        }
    }

    if (payloadDecrypted)
    {
        wcout << L"success" << endl;
        WritePayloadToDisk(Filename, OutputFolder, payloadBuffer, resourceSize);
    }
    else
    {
        wcout << L"decryption failed" << endl;
    }
    VirtualFree(payloadBuffer, resourceSize, MEM_RELEASE);
}

BOOL HandleFile(const wstring& FilePath, const wstring& OutputFolder)
{
    // get the filename from the complete path
    const wstring baseName = FilePath.substr(FilePath.find_last_of(L'\\') + 1);

    //print the left column of the csv report
    wcout << baseName << ",";

    // load the file as a module to access resources
    const HMODULE moduleHandle = LoadLibraryEx(FilePath.c_str(), nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (nullptr == moduleHandle)
    {
        wcout << L"Loading file failed" << endl;
        return false;
    }

    ExtractPayload(moduleHandle, baseName, OutputFolder);

    FreeLibrary(moduleHandle);
    return true;
}

void IterateFolder(const wstring& FolderPath, const wstring& OutputFolder)
{
    for (auto& directoryEntry : recursive_directory_iterator(FolderPath))
    {
        if (directoryEntry.is_regular_file())
            HandleFile(directoryEntry.path(), OutputFolder);
    }
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    // get command line values
    wstring outputDir;
    if (1 == argc)
    {
        wcout << L"usage: emotet_unpacker.exe EMOTET_LOADERS_DIR [PAYLOADS_DIR]" << endl;
        return EXIT_FAILURE;
    }
    if (3 == argc)
    {
        outputDir.assign(argv[2]);
        CreateOutputFolders(outputDir);
    }

    const wstring loadersDir = argv[1];
    wcout << L"hash,result" << endl;
    IterateFolder(loadersDir, outputDir);
    return EXIT_SUCCESS;
}
