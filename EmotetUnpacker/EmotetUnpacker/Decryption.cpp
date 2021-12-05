#include "Decryption.h"

void Decryption::XorDecryption(uint8_t* Buffer, const uint32_t BufferSize, const unsigned char* Key, const uint32_t KeySize)
{
	for (int i = 0; i < BufferSize; i++)
	{
		Buffer[i] ^= Key[i % KeySize];
	}
}

bool ResourceDecryption::Decrypt(uint8_t* Buffer, const uint32_t Size)
{
	const auto encryptedMagic = *reinterpret_cast<uint32_t*>(Buffer);
	for (auto const& [knownEncryptedMagic, Key] : g_XorKeys)
	{
		if (encryptedMagic == knownEncryptedMagic)
		{
			XorDecryption(Buffer, Size, Key.data(), Key.size());
			return true;
		}
	}
	return false;
}

bool DataSectionDecryption::Decrypt(uint8_t* Buffer, const uint32_t Size)
{
	constexpr auto initStr = "lEZ4zx89^n^orFIbWKOvbN1Kp4M&%G+77OI^Bna85p8yypN_4Oe#lJbL*Uoq@YZ_FT&Q^_87STI7?hC60A0&d*bMP@?N5";
	constexpr int keySize = 0x628F;
	const auto key = new uint8_t[keySize];
	BuildKey(key, keySize, initStr, strlen(initStr) + 1);
	unsigned int val1 = 0;
	unsigned int val2 = 0;
	for (int i = 0; i < Size; i++)
	{
		val1 = (val1 + 1) % keySize;
		const unsigned int val3 = (key[val1] + val2) % keySize;
		const char val4 = key[val1];
		key[val1] = key[val3];
		key[val3] = val4;
		val2 = val3;
		Buffer[i] ^= key[((key[val3] + key[val1]) % keySize)];
	}
	delete[] key;
	return true;
}

void DataSectionDecryption::BuildKey(uint8_t* KeyBuffer, const int KeyBufferSize, const char* InitStr, const int InitStrSize)
{
	auto tmpBuffer = new char[KeyBufferSize];
	for (int i = 0; i < KeyBufferSize; i++)
	{
		KeyBuffer[i] = i;
		tmpBuffer[i] = InitStr[i % InitStrSize];
	}
	unsigned int indexToSwitch = 0;
	for (int i = 0; i < KeyBufferSize; i++)
	{
		indexToSwitch = (indexToSwitch + KeyBuffer[i] + tmpBuffer[i]) % KeyBufferSize;
		const char valueToSwitch = KeyBuffer[i];
		KeyBuffer[i] = KeyBuffer[indexToSwitch];
		KeyBuffer[indexToSwitch] = valueToSwitch;
	}
	delete[] tmpBuffer;
}