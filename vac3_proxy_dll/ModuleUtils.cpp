#include "ModuleUtils.hpp"

#include <iostream>
#include <Windows.h>

//Shitty C&P
bool DataCompare(const BYTE* OpCodes, const BYTE* Mask, const char* StrMask)
{
	//solange bis String zuende  
	while (*StrMask)
	{
		//wenn Byte ungleich --> false  
		if (*StrMask == 'x' && *OpCodes != *Mask)
			return false;

		++StrMask;
		++OpCodes;
		++Mask;
	}

	return true;  //wenn alle Bytes gleich  
}

DWORD FindPattern(DWORD StartAddress, DWORD CodeLen, BYTE* Mask, char* StrMask, unsigned short ignore)
{
	unsigned short Ign = 0;
	DWORD i = 0;

	while (Ign <= ignore)
	{
		if (DataCompare((BYTE*)(StartAddress + i++), Mask, StrMask))
			++Ign;

		else if (i >= CodeLen)
			return 0;
	}
	return StartAddress + i - 1;
}

int __stdcall GetVACProcIndex(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, unsigned long ModuleBase)
{
	struct ProcStruct
	{
		unsigned long NextProc;
		unsigned long Checksum1;
		unsigned long Checksum2;
		unsigned long ProcAddress;
		unsigned long XorTable;
	};

	if (Module.empty())
	{
		throw std::exception("Module is empty");
		return -1;
	}

	if (VacIn.empty())
	{
		throw std::exception("VacIn is empty");
		return -1;
	}

	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)Module.data();
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	if (ntHeader->FileHeader.NumberOfSections < 3)
	{
		throw std::exception("Invalid NumberOfSections");
		return -1;
	}

	auto pSecHeader = IMAGE_FIRST_SECTION(ntHeader);
	bool foundSection = false;

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
	{
		pSecHeader = IMAGE_FIRST_SECTION(ntHeader) + i;

		if (strcmp((char*)pSecHeader->Name, ".data") == 0)
		{
			foundSection = true;
			break;
		}
	}

	if (!foundSection)
	{
		throw std::exception("Cannot find section");
	}

	auto dataSectionPtr = (ModuleBase + pSecHeader->VirtualAddress);

	//Find all XorTables
	std::vector<ProcStruct*> ProcTable;
	unsigned long PatternResult = dataSectionPtr;

	do
	{
		PatternResult = FindPattern(dataSectionPtr, 0x200 + (ProcTable.size() * 0x200), (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "????????xxxx????????????????????????????????????xxxx", ProcTable.size());

		if (PatternResult)
		{
			ProcTable.push_back((ProcStruct*)PatternResult);

			if (ProcTable.size() >= 10)
				break;
		}
	} while (PatternResult);

	//Find the right one
	if (ProcTable.empty())
	{
		throw std::exception("ProcTable is empty");
		return -1;
	}

	for (int i = 0; i < ProcTable.size(); ++i)
	{
		unsigned long VACChecksum1 = *(unsigned long*)VacIn.data();
		unsigned long VACChecksum2 = *(unsigned long*)(VacIn.data() + 0x4);

		if (ProcTable.at(i)->Checksum1 == VACChecksum1 && ProcTable.at(i)->Checksum2 == VACChecksum2)
			return i;
	}

	return -1;
}
