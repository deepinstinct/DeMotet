#include "PeFile.h"

PeFile::PeFile(const wstring& Path) : m_Path(Path)
{
    ReadFromFile(Path, m_Data);
    m_FileSize = m_Data.size();
    m_DataStart = m_Data.data();
    m_DataEnd = m_DataStart + m_FileSize;
    ValidatePeFormat();
}

PeFile::PeFile(const vector<uint8_t>& FileData)
{
    m_Data = FileData;
    m_FileSize = m_Data.size();
    m_DataStart = m_Data.data();
    m_DataEnd = m_DataStart + m_FileSize;
    ValidatePeFormat();
}

void PeFile::DosHeaderValid()
{
    m_DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_DataStart);

    // verify the file is large enough to contain the dos header to avoid memory access violation
    if (m_DataEnd < m_DataStart + sizeof(IMAGE_DOS_HEADER))
        throw runtime_error("parsing error: size too small to have dos header");

    // verify the file starts with MZ
    if (m_DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        throw runtime_error("parsing error: dos signature not found");
}

void PeFile::NtHeadersValid()
{
    m_NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>(m_DataStart + m_DosHeader->e_lfanew);
    m_FileHeader = &m_NtHeaders->FileHeader;
    m_OptionalHeader = &m_NtHeaders->OptionalHeader;
    m_DataDirectories = m_OptionalHeader->DataDirectory;

    // verify the pointer to the NT header is inside the buffer of the file
    if (m_DosHeader->e_lfanew > m_FileSize)
        throw runtime_error("parsing error: IMAGE_DOS_HEADER.e_lfanew is invalid");

    uint8_t* ntHeadersEnd = m_DataStart + m_DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32);

    // verify the file is large enough to contain the NT headers
    if (m_DataEnd < ntHeadersEnd)
        throw runtime_error("parsing error: size too small to have nt headers");

    // verify the file contains PE signature
    if (m_NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        throw runtime_error("parsing error: PE signature not found");

    // verify the file is 32bit
    if (m_NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        throw runtime_error("parsing error: file is not 32bit");
}

void PeFile::SectionHeadersValid()
{
    // the sections headers start after the optional header. The size of the optional header is specified in the file header
    uint8_t* sectionHeadersAddress = reinterpret_cast<uint8_t*>(m_OptionalHeader) + m_FileHeader->SizeOfOptionalHeader;

    // verify the pointer to the sections headers is inside the buffer of the file
    if (sectionHeadersAddress < m_DataStart || sectionHeadersAddress >= m_DataEnd)
        throw runtime_error("parsing error: section table address is invalid");

    m_SectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(sectionHeadersAddress);
    uint16_t sectionsCount = 0;
    for (; sectionsCount < m_FileHeader->NumberOfSections; sectionsCount++)
    {
        uint8_t* sectionHeaderEnd = sectionHeadersAddress + (IMAGE_SIZEOF_SECTION_HEADER * (sectionsCount + 1));

        // verify the file is large enough to contain the current section header to avoid memory access violation
        if (sectionHeaderEnd > m_DataEnd)
            throw runtime_error("parsing error: section header ends after buffer");

        uint8_t* sectionEnd = m_DataStart + m_SectionHeaders[sectionsCount].PointerToRawData + m_SectionHeaders[sectionsCount].SizeOfRawData;
        if (sectionEnd > m_DataEnd)
            throw runtime_error("parsing error: section data ends after buffer");

        // stop counting  headers if the current header is empty
        if (IsSectionHeaderEmpty(&m_SectionHeaders[sectionsCount]))
            break;
    }

    // verify that NumberOfSections matches number of actual headers
    if (sectionsCount != m_FileHeader->NumberOfSections)
        throw runtime_error("parsing error: NumberOfSections doesn't match number of headers found");
}

void PeFile::ValidatePeFormat()
{
    DosHeaderValid();
    NtHeadersValid();
    SectionHeadersValid();
}

bool PeFile::DataDirIndexInvalid(const uint32_t DirIndex) const
{
    // verify that dir_index isn't exceeding the array
    return DirIndex > m_OptionalHeader->NumberOfRvaAndSizes - 1;

}

PIMAGE_SECTION_HEADER PeFile::GetSectionHeaderForVa(const uint32_t VirtualAddress, uint16_t* SectionIndex) const
{
    // iterate over the sections headers
    const uint16_t numberOfSections = m_FileHeader->NumberOfSections;
    for (uint16_t i = 0; i < numberOfSections; i++)
    {
	    const PIMAGE_SECTION_HEADER currentSectionHeader = &m_SectionHeaders[i];
	    const uint32_t sectionVirtualAddress = currentSectionHeader->VirtualAddress;
	    const uint32_t sectionSize = currentSectionHeader->Misc.VirtualSize;

        // check if the VA is inside the range of this section's virtual addresses
        if (VirtualAddress >= sectionVirtualAddress && VirtualAddress < (sectionVirtualAddress + sectionSize))
        {
            if (nullptr != SectionIndex)
                *SectionIndex = i;
            return currentSectionHeader;
        }
    }
    return nullptr;

}

uint8_t* PeFile::VirtualAddressToRawAddress(const uint32_t VirtualAddress) const
{
	const PIMAGE_SECTION_HEADER relatedSectionHeader = GetSectionHeaderForVa(VirtualAddress);
    if (nullptr != relatedSectionHeader)
    {
        // find the offset of the VA inside the section
        const uint32_t sectionVirtualAddress = relatedSectionHeader->VirtualAddress;
        const uint32_t offsetInSection = VirtualAddress - sectionVirtualAddress;

        // add this offset to the PointerToRawData to find the offset inside the file 
        const uint32_t sectionRawDataPointer = relatedSectionHeader->PointerToRawData;
        const uint32_t rawOffset = sectionRawDataPointer + offsetInSection;

        // add the offset inside the file to the base address of the buffer
        uint8_t* rawAddress = m_DataStart + rawOffset;
        return rawAddress;
    }
    return nullptr;

}

uint32_t PeFile::GetDataDirVirtualAddress(const uint32_t DirIndex) const
{
    if (DataDirIndexInvalid(DirIndex))
        return 0;
    return m_DataDirectories[DirIndex].VirtualAddress;

}

uint32_t PeFile::GetDataDirSize(const uint32_t DirIndex) const
{
    if (DataDirIndexInvalid(DirIndex))
        return 0;
    return m_DataDirectories[DirIndex].Size;
}

uint8_t* PeFile::GetDataDirRawAddress(const uint32_t DirIndex) const
{
	const uint32_t dataDirVirtualAddress = GetDataDirVirtualAddress(DirIndex);
    if (0 != dataDirVirtualAddress)
        return VirtualAddressToRawAddress(dataDirVirtualAddress);
    return nullptr;

}


bool PeFile::IsStructEmpty(const uint8_t* StructPointer, const uint32_t StructSize)
{
    for (uint32_t i = 0; i < StructSize; i++)
    {
        if (StructPointer[i] != 0)
        {
            return false;
        }
    }
    return true;
}

auto PeFile::IsSectionHeaderEmpty(const PIMAGE_SECTION_HEADER SectionHeader) -> bool
{
    // casting the section_header as uint8_t* in order the access each byte in the buffer separately
    return IsStructEmpty(reinterpret_cast<uint8_t*>(SectionHeader), IMAGE_SIZEOF_SECTION_HEADER);
}

PIMAGE_RESOURCE_DATA_ENTRY PeFile::FindResourceDataEntry(const PIMAGE_RESOURCE_DIRECTORY ResourceDirectory, const uint32_t ResourceDirectorySize, uint8_t* ResourcesRoot,
                                                         const uint32_t RecursionLevel, const LPCWSTR TargetType, const LPCWSTR TargetName) const
{
    PIMAGE_RESOURCE_DIRECTORY_ENTRY dirEntry = nullptr;
    LPCWSTR targetIdentifier = nullptr;
    if (RESOURCE_LEVEL_TYPE == RecursionLevel)
    {
        targetIdentifier = TargetType;
    }
    else if (RESOURCE_LEVEL_NAME == RecursionLevel)
    {
        targetIdentifier = TargetName;
    }
    uint32_t numOfEntries = 0;

    // ID entries come after named entries. If the target identifier is an integer and not a string, we skip named entries
    if (IS_INTRESOURCE(targetIdentifier))
    {
        numOfEntries = ResourceDirectory->NumberOfIdEntries;
        dirEntry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(reinterpret_cast<uint8_t*>(ResourceDirectory) + sizeof(IMAGE_RESOURCE_DIRECTORY) + (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * ResourceDirectory->NumberOfNamedEntries));
    }
    else
    {
        numOfEntries = ResourceDirectory->NumberOfNamedEntries;

        // the named directory struct starts after the resource directory struct
        dirEntry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(reinterpret_cast<uint8_t*>(ResourceDirectory) + sizeof(IMAGE_RESOURCE_DIRECTORY));
    }

    // check if the values in the entry are valid
    if ((dirEntry->NameOffset > ResourceDirectorySize && dirEntry->NameIsString) ||
        (dirEntry->OffsetToDirectory > ResourceDirectorySize && dirEntry->DataIsDirectory))
        return nullptr;

    for (WORD i = 0; i < numOfEntries; i++)
    {
        if (dirEntry->DataIsDirectory)
        {
            bool identifiersMatch = false;

            // check that the identifier of the current directory and the target identifier are both strings
            if (dirEntry->NameIsString)
            {
                if (!IS_INTRESOURCE(targetIdentifier))
                {
                    const auto directoryStringStruct = reinterpret_cast<PIMAGE_RESOURCE_DIR_STRING_U>(ResourcesRoot + dirEntry->NameOffset);
                    wstring currentDirectoryString(directoryStringStruct->NameString, directoryStringStruct->Length);
                    wstring targetString = targetIdentifier;
                    identifiersMatch = !currentDirectoryString.compare(targetString);
                }
            }
            else
            {
                // check that the identifier of the current directory and the target identifier are both integers
                if (IS_INTRESOURCE(targetIdentifier))
                    identifiersMatch = reinterpret_cast<uint16_t>(targetIdentifier) == dirEntry->Id;
            }

            // the offset of the dir entry needs to be added to the beginning of the resource section
            const auto nextDir = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(ResourcesRoot + dirEntry->OffsetToDirectory);
            
            // the resource directory has 3 level. In each level the ID is for a different property: type, name and language
            if (RESOURCE_LEVEL_TYPE == RecursionLevel && identifiersMatch)
            {
                // if the correct type was found, search all the name directories under it
                return FindResourceDataEntry(nextDir, ResourceDirectorySize, ResourcesRoot, RecursionLevel + 1, TargetType, TargetName);
            }
            if (RESOURCE_LEVEL_NAME == RecursionLevel && identifiersMatch)
            {
                // if the correct type was found, search all the language directories under it
                return FindResourceDataEntry(nextDir, ResourceDirectorySize, ResourcesRoot, RecursionLevel + 1, TargetType, TargetName);
            }
            // the recursion reached the language directory
            // the language directory shouldn't have IMAGE_RESOURCE_DIRECTORY under it, only IMAGE_RESOURCE_DATA_ENTRY
            if (RESOURCE_LEVEL_LANG == RecursionLevel)
				return nullptr;
        }
        else
        {
            // the IMAGE_RESOURCE_DATA_ENTRY has to be under the language directory and not before that
            if (RESOURCE_LEVEL_LANG == RecursionLevel)
            {
	            const auto entry = reinterpret_cast<PIMAGE_RESOURCE_DATA_ENTRY>(ResourcesRoot + dirEntry->OffsetToData);
                return entry;
            }
        }
        dirEntry++;
    }
    return nullptr;
}


bool PeFile::GetResource(const LPCWSTR Type, const LPCWSTR Name, vector<uint8_t>& ResourceVector) const
{
    uint8_t* resourceSection = GetDataDirRawAddress(IMAGE_DIRECTORY_ENTRY_RESOURCE);
    const uint32_t resourceSize = GetDataDirSize(IMAGE_DIRECTORY_ENTRY_RESOURCE);

    // if the resource dir doesn't exist there is nothing to search for
    if (nullptr == resourceSection || 0 == resourceSize)
        return false;

    const auto resourceDataEntry = FindResourceDataEntry(reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(resourceSection), resourceSize, resourceSection, RESOURCE_LEVEL_TYPE, Type, Name);
    if (nullptr == resourceDataEntry)
        return false;

    // check that the values in the resource entry are valid
    uint8_t* resourceDataStart = VirtualAddressToRawAddress(resourceDataEntry->OffsetToData);
    uint8_t* resourceDataEnd = resourceDataStart + resourceDataEntry->Size;
    if (nullptr == resourceDataStart || resourceDataEnd > m_DataEnd)
        return false;

    // copy the resource data into the vector
    ResourceVector.insert(ResourceVector.begin(), resourceDataStart, resourceDataEnd);
    return true;
}
