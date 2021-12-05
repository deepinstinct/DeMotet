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