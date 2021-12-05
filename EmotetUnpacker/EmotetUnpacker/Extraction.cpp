#include "Extraction.h"

LPCWSTR g_EncryptedResourceType = RT_BITMAP;
LPCWSTR g_EncryptedResourceName = MAKEINTRESOURCE(0xC9);

bool ResourceExtraction::Extract(PeFile* Pe, vector<uint8_t>& EncryptedDataVector)
{
	vector<uint8_t> resourceVector;
	if (!Pe->GetResource(g_EncryptedResourceType, g_EncryptedResourceName, resourceVector))
		return false;

	// The encrypted data starts after 0x67 bytes
	EncryptedDataVector.insert(EncryptedDataVector.begin(), resourceVector.begin() + ENCRYPTED_DATA_OFFSET, resourceVector.end());
	return true;
}

bool DataSectionExtraction::Extract(PeFile* Pe, vector<uint8_t>& EncryptedDataVector)
{
	/* the size of the encrypted payload is specified in the call to VirtualAlloc. Search for:
	push    40h
	push    3000h
	push    X
	*/
	const vector<uint8_t> virtualAllocParameters = {	0x6A, 0x40, // push 40h
														0x68, 0x00, 0x30, 0x00, 0x00, // push 3000h
														0x68 }; // push X
	const uint32_t virtualAllocCallIndex = Pe->SearchForData(virtualAllocParameters);

	// check if the bytes sequence was found
	if (!virtualAllocCallIndex)
		return false;

	// read the value of the 3rd PUSH instruction
	uint32_t encryptedPayloadSize = 0;
	if (!Pe->ReadInt32(virtualAllocCallIndex + virtualAllocParameters.size(), &encryptedPayloadSize))
		return false;

	// search for strings in the file that are used to build the decryption key
	for (auto const& [keySize, initStr] : DataSectionDecryption::m_Keys)
	{
		if (const uint32_t initStrIndex = Pe->SearchForData(initStr))
		{
			// the init string starts right after the encrypted payload
			const uint32_t encryptedDataStart = initStrIndex - encryptedPayloadSize;
			if (Pe->ReadBytes(encryptedDataStart, encryptedPayloadSize, EncryptedDataVector))
			{
				// tell the decryption class which key should be used
				DataSectionDecryption::m_KeySize = keySize;
				return true;
			}
		}
	}
	return false;
}