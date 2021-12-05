#include "Utils.h"

double CalcEntropy(const uint8_t* BufferStart, const uint8_t* BufferEnd) {
    vector<char> stvec(BufferStart, BufferEnd);
    set<char> alphabet(stvec.begin(), stvec.end());
    vector<double> frequencies;
    for (auto c = alphabet.begin(); c != alphabet.end(); ++c) {
        int ctr = 0;
        for (auto s = stvec.begin(); s != stvec.end(); ++s) {
            if (*s == *c) {
                ++ctr;
            }
        }
        frequencies.push_back(static_cast<double>(ctr) / static_cast<double>(stvec.size()));
    }
    double ent = 0;
    const double ln2 = log(2);
    for (auto f = frequencies.begin(); f != frequencies.end(); ++f) {
        ent += *f * log(*f) / ln2;
    }
    ent = -ent;
    return ent;
}

void ReadFromFile(const wstring& FilePath, vector<uint8_t>& DataVector)
{
    ifstream fileStream(FilePath, std::ios::binary);
    if (fileStream.bad())
    {
        string errorMsg = "Error reading from ";
        errorMsg.append(FilePath.begin(), FilePath.end());
        throw runtime_error(errorMsg);
    }
    DataVector.assign(std::istreambuf_iterator(fileStream), {});
}

void WriteToFile(const wstring& FilePath, vector<uint8_t>& DataVector)
{
    auto fileStream = ofstream(FilePath, std::ios::binary);
    if (fileStream.bad())
    {
        string errorMsg = "Error writing to ";
        errorMsg.append(FilePath.begin(), FilePath.end());
        throw runtime_error(errorMsg);
    }
    fileStream.write(reinterpret_cast<char*>(DataVector.data()), DataVector.size());
    fileStream.close();
}

void WritePayloadToDisk(const wstring& Filename, const wstring& OutputFolder, vector<uint8_t>& PayloadVector)
{
    // build the path for the payload
    wstring payloadPath(OutputFolder);
    payloadPath.append(PAYLOADS_FOLDER_NAME);
    payloadPath.append(Filename);
    payloadPath.append(PAYLOAD_SUFFIX);
    WriteToFile(payloadPath, PayloadVector);
}

void CreateOutputFolder(const wstring& OutputFolder)
{
    if (!is_directory(OutputFolder))
    {
        create_directory(OutputFolder);
    }

    wstring payloadsFolder(OutputFolder);
    payloadsFolder.append(PAYLOADS_FOLDER_NAME);
    create_directory(payloadsFolder);
}