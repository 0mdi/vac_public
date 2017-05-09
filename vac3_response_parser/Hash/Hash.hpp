#pragma once
#include <string>

std::string HashPEHeader(unsigned char* ModuleData);

constexpr unsigned int str2int(const char* str, int h = 0)
{
	return !str[h] ? 5381 : (str2int(str, h + 1) * 33) ^ str[h];
}