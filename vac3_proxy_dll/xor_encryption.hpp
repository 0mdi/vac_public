#pragma once

char* xor_encrypt_decrypt(char *key, int keySize, char *input, int size)
{
	for (int i = 0; i < size; ++i)
		input[i] = input[i] ^ key[i % keySize];

	return input;
}