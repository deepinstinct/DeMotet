#include "Utils.h"

double CalcEntropy(const PBYTE BufferStart, const PBYTE BufferEnd) {
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

BOOL ResourceTypeNotRelevant(const LPWSTR Type)
{
    return (Type != RT_BITMAP);
}

BOOL CALLBACK EnumResNameProc(const HMODULE ModuleHandle, const LPWSTR Type, const LPWSTR Name, ResourceInfo* ResourceInfo)
{
    // Skip resources to improve performance
    if (ResourceTypeNotRelevant(Type))
        return true;

    const HRSRC resourceHandle = FindResourceW(ModuleHandle, Name, Type);
    if (nullptr == resourceHandle)
        return true;

    const DWORD resourceSize = SizeofResource(ModuleHandle, resourceHandle);
    const HGLOBAL globalHandle = LoadResource(ModuleHandle, resourceHandle);
    if (nullptr == globalHandle)
        return true;

    const auto resourceAddress = static_cast<PBYTE>(LockResource(globalHandle));
    if (nullptr == resourceAddress)
        return TRUE;

    const PBYTE resourceEnd = resourceAddress + resourceSize;

    // the resource with the highest entropy usually has the encrypted payload
    const double resourceEntropy = CalcEntropy(resourceAddress, resourceEnd);
    if (resourceEntropy > ResourceInfo->ResourceEntropy)
    {
        ResourceInfo->ResourceType = Type;
        ResourceInfo->ResourceName = Name;
        ResourceInfo->ResourceSize = resourceSize;
        ResourceInfo->ResourceAddress = resourceAddress;
        ResourceInfo->ResourceEntropy = resourceEntropy;
    }
    return true;
}

BOOL CALLBACK EnumResTypeProc(const HMODULE ModuleHandle, const LPWSTR Type, ResourceInfo* ResourceInfo)
{
    EnumResourceNamesW(ModuleHandle, Type, reinterpret_cast<ENUMRESNAMEPROCW>(EnumResNameProc), reinterpret_cast<LONG_PTR>(ResourceInfo));
    return true;
}

bool FindEncryptedResource(const HMODULE ModuleHandle, ResourceInfo* ResourceInfo)
{
    EnumResourceTypesW(ModuleHandle, reinterpret_cast<ENUMRESTYPEPROCW>(EnumResTypeProc), reinterpret_cast<LONG_PTR>(ResourceInfo));

    // check if a resource with entropy high enough to contain encrypted data was found
    return ResourceInfo->ResourceEntropy > ENTROPY_THRESHOLD;
}

bool WriteToFile(const wstring& FilePath, const PBYTE Data, const DWORD DataSize)
{
	const HANDLE fileHandle = CreateFileW(FilePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (INVALID_HANDLE_VALUE == fileHandle)
    {
        return false;
    }
    DWORD bytesWritten;
	const bool writeSuccess = WriteFile(fileHandle, Data, DataSize, &bytesWritten, nullptr);
    CloseHandle(fileHandle);
    return writeSuccess;
}

bool WritePayloadToDisk(const wstring& Filename, const wstring& OutputFolder, const PBYTE PayloadBuffer, const DWORD PayloadSize)
{
    // build the path for the payload
    wstring payloadPath(OutputFolder);
    payloadPath.append(PAYLOADS_FOLDER_NAME);
    payloadPath.append(Filename);
    payloadPath.append(PAYLOAD_SUFFIX);
    return WriteToFile(payloadPath, PayloadBuffer, PayloadSize);
}

void CreateOutputFolders(const wstring& OutputDir)
{
    if (!PathFileExistsW(OutputDir.c_str()))
    {
        CreateDirectoryW(OutputDir.c_str(), nullptr);
    }

    wstring payloadsFolder(OutputDir);
    payloadsFolder.append(PAYLOADS_FOLDER_NAME);
    CreateDirectoryW(payloadsFolder.c_str(), nullptr);
}