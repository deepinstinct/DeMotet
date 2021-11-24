#pragma once
#include <Windows.h>
#include <shlwapi.h>
#include <string>
#include <iostream>
#include <vector>
#include <set>

using std::wstring;
using std::wcout;
using std::endl;
using std::vector;
using std::set;

struct ResourceInfo {
    LPWSTR ResourceType;
    LPWSTR ResourceName;
    DWORD  ResourceSize;
    PBYTE  ResourceAddress;
    double ResourceEntropy;
};

const wstring PAYLOADS_FOLDER_NAME(L"\\payloads\\");
const wstring PAYLOAD_SUFFIX(L"_payload.bin");
constexpr double ENTROPY_THRESHOLD = 7.0;

void XorDecryption(PBYTE Buffer, DWORD BufferSize, const unsigned char* Key, DWORD KeySize);
bool FindEncryptedResource(HMODULE ModuleHandle, ResourceInfo* ResourceInfo);
bool WritePayloadToDisk(const wstring& Filename, const wstring& OutputFolder, PBYTE PayloadBuffer, DWORD PayloadSize);
void CreateOutputFolders(const wstring& OutputDir);