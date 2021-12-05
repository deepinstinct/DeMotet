#pragma once
#include "stdafx.h"
#include "Utils.h"

constexpr int RESOURCE_LEVEL_TYPE = 0;
constexpr int RESOURCE_LEVEL_NAME = 1;
constexpr int RESOURCE_LEVEL_LANG = 2;

struct ResourceInfo {
	LPWSTR ResourceType;
	LPWSTR ResourceName;
	DWORD  ResourceSize;
	PBYTE  ResourceAddress;
	double ResourceEntropy;
};

class PeFile
{
public:
	explicit PeFile(const wstring& Path);
	explicit PeFile(const vector<uint8_t>& FileData);
	bool GetResource(LPCWSTR Type, LPCWSTR Name, vector<uint8_t>& ResourceVector) const;

private:
	wstring m_Path;
	vector<uint8_t> m_Data;
	uint32_t m_FileSize = 0;
	uint8_t* m_DataStart = nullptr;
	uint8_t* m_DataEnd = nullptr;

	// pointers to important headers
	PIMAGE_DOS_HEADER m_DosHeader = nullptr;
	PIMAGE_NT_HEADERS32 m_NtHeaders = nullptr;
	PIMAGE_FILE_HEADER m_FileHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER32 m_OptionalHeader = nullptr;
	PIMAGE_DATA_DIRECTORY m_DataDirectories = nullptr;
	PIMAGE_SECTION_HEADER m_SectionHeaders = nullptr;
	
	// validate PE format
	void DosHeaderValid();
	void NtHeadersValid();
	void SectionHeadersValid();
	void ValidatePeFormat();
	bool DataDirIndexInvalid(uint32_t DirIndex) const;

	// calculate addresses
	PIMAGE_SECTION_HEADER GetSectionHeaderForVa(uint32_t VirtualAddress, uint16_t* SectionIndex = nullptr) const;
	uint8_t* VirtualAddressToRawAddress(uint32_t VirtualAddress) const;
	uint32_t GetDataDirVirtualAddress(uint32_t DirIndex) const;
	uint32_t GetDataDirSize(uint32_t DirIndex) const;
	uint8_t* GetDataDirRawAddress(uint32_t DirIndex) const;

	// used for iterating arrays
	static bool IsStructEmpty(const uint8_t* StructPointer, uint32_t StructSize);
	static bool IsSectionHeaderEmpty(PIMAGE_SECTION_HEADER SectionHeader);

	// resources methods
	PIMAGE_RESOURCE_DATA_ENTRY FindResourceDataEntry(PIMAGE_RESOURCE_DIRECTORY ResourceDirectory, uint32_t ResourceDirectorySize, uint8_t* ResourcesRoot,
													uint32_t RecursionLevel, LPCWSTR TargetType, LPCWSTR TargetName) const;
};