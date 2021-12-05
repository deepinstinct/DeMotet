#pragma once
#include "stdafx.h"
#include "PeFile.h"
#include "Decryption.h"

class Extraction
{
public:
    virtual bool Extract(PeFile* Pe, vector<uint8_t>& EncryptedDataVector) = 0;
};

// The encrypted data starts after 0x67 bytes
constexpr unsigned int ENCRYPTED_DATA_OFFSET = 0x67;

class ResourceExtraction : public Extraction
{
public:
	ResourceExtraction() = default;
	bool Extract(PeFile* Pe, vector<uint8_t>& EncryptedDataVector) override;
};

class DataSectionExtraction : public Extraction
{
public:
	DataSectionExtraction() = default;
	bool Extract(PeFile* Pe, vector<uint8_t>& EncryptedDataVector) override;
};