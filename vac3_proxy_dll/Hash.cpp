#include "Hash.hpp"
#include "MD5.h"

#include <Windows.h>

DWORD SizeOfPEHeader(const IMAGE_NT_HEADERS * pNTH)
{
	return (offsetof(IMAGE_NT_HEADERS, OptionalHeader) + pNTH->FileHeader.SizeOfOptionalHeader + (pNTH->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
}

std::string HashPEHeader(unsigned char* ModuleData)
{
	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)ModuleData;
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	auto peSize = SizeOfPEHeader(ntHeader);

	return md5((char*)ntHeader, peSize);
}