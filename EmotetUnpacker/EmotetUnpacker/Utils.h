#pragma once
#include "stdafx.h"

const wstring PAYLOADS_FOLDER_NAME(L"\\payloads\\");
const wstring PAYLOAD_SUFFIX(L"_payload.bin");

double CalcEntropy(const uint8_t* BufferStart, const uint8_t* BufferEnd);
void ReadFromFile(const wstring& FilePath, vector<uint8_t>& DataVector);
void WriteToFile(const wstring& FilePath, vector<uint8_t>& DataVector);
void WritePayloadToDisk(const wstring& Filename, const wstring& OutputFolder, vector<uint8_t>& PayloadVector);
void CreateOutputFolder(const wstring& OutputFolder);