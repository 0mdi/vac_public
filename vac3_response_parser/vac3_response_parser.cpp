#include <Windows.h>

#include <string>
#include <vector>

#include <iostream>

#include "Modules/ModuleParser.hpp"
#include "Preprocessor/Preprocessor.hpp"
#include "ModuleUtils.hpp"

#define PROC_LIMIT 10


struct ProcStruct
{
	unsigned long NextProc;
	unsigned long Checksum1;
	unsigned long Checksum2;
	unsigned long ProcAddress;
	unsigned long XorTable;
};


/**
  * Does some special stuff like hooking some functions to ensure safety before calling runfunc
*/
__declspec(dllexport) bool __stdcall PreprocessModule(const std::vector<unsigned char>& ModuleVec, unsigned long ModuleBase)
{
	return Preprocessor::Preprocess(ModuleVec, ModuleBase);
}

/**
  * Receive generated output by VAC3 and Parse & Correct it to avoid bans
*/
__declspec(dllexport) bool __stdcall ParseVAC3Output(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	return ModuleParser::ParseModule(ModuleVec, FunctionId, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
}

/**
  * Decrypts VAC Data
  * /throws dunno a few exceptions on error maybe?
*/
__declspec(dllexport) std::vector<unsigned char> __stdcall DecryptVACData(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, const std::vector<unsigned char> &Encrypted, unsigned long ModuleBase, bool doXor)
{
	if (Module.empty())
		throw std::exception("DecryptVACData: Module is empty");

	if (Encrypted.empty())
		throw std::exception("DecryptVACData: Encrypted data is empty");

	//Load VAC_8600.dll for encryption
	auto EncryptionModule = LoadLibraryA("C:/VAC_8600.dll");

	if (EncryptionModule == nullptr)
		throw std::exception("DecryptVACData: Cannot load EncryptionModule");


	//Search for encryption function
	using InitializeEncryptionTablesType = int(*__cdecl)(unsigned char *VacInputOffset16, unsigned char *Out, int Size, unsigned char *Table);
	InitializeEncryptionTablesType InitializeEncryptionTables = nullptr;

	InitializeEncryptionTables = (InitializeEncryptionTablesType)FindPattern((DWORD)EncryptionModule, 0x4000, (BYTE*)"\x55\x8B\xEC\x83\xEC\x0C\x8D", "xxxxxxx", 0);

	if (InitializeEncryptionTables == nullptr)
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACData: Cannot resolve encryption");
	}

	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)Module.data();
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	if (ntHeader->FileHeader.NumberOfSections < 3)
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACData: Invalid NumberOfSections");
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
		FreeLibrary(EncryptionModule);
		throw std::exception("Cannot find section");
	}

	auto dataSectionPtr = (((unsigned long)ModuleBase) + pSecHeader->VirtualAddress);

	//Find all XorTables
	std::vector<ProcStruct*> ProcTable;
	unsigned long PatternResult = 0;

	do
	{
		PatternResult = FindPattern(dataSectionPtr, 0x200 + (ProcTable.size() * 0x200), (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "????????xxxx????????????????????????????????????xxxx", ProcTable.size());

		if (PatternResult)
		{
			ProcTable.push_back((ProcStruct*)PatternResult);

			if (ProcTable.size() >= PROC_LIMIT)
				break;
		}

	} while (PatternResult != 0);

	//Find the right one
	unsigned long* xorTable = nullptr;

	if (ProcTable.empty())
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACData: ProcTable is empty");
	}

	for (auto Proc : ProcTable)
	{
		unsigned long VACChecksum1 = *(unsigned long*)VacIn.data();
		unsigned long VACChecksum2 = *(unsigned long*)(VacIn.data() + 0x4);

		if (Proc->Checksum1 == VACChecksum1 && Proc->Checksum2 == VACChecksum2)
		{
			xorTable = &Proc->XorTable;
			break;
		}
	}

	if (xorTable == nullptr)
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACData: Cannot locate XorTable");
	}

	unsigned int GeneratedTable[44];
	InitializeEncryptionTables((unsigned char*)VacIn.data() + 16, (unsigned char*)GeneratedTable, sizeof(GeneratedTable), (unsigned char*)xorTable);

	auto xorKey = GeneratedTable[25];

	//Decrypt XOR
	std::vector<unsigned char> Decrypted;
	Decrypted.resize(Encrypted.size());
	InitializeEncryptionTables((unsigned char*)Encrypted.data(), Decrypted.data(), Encrypted.size(), ((unsigned char*)GeneratedTable) + 0x10);

	if (doXor)
	{
		for (int i = 0; i < (Decrypted.size() - 12) / 4; ++i)
			((int*)Decrypted.data())[i + 3] ^= xorKey;
	}

	FreeLibrary(EncryptionModule);
	return Decrypted;
}

/*
 * Decrypts VAC In Data
 * /trows dunno a few exceptions on error maybe?
*/
__declspec(dllexport) std::vector<unsigned char> __stdcall DecryptVACIn(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, unsigned long ModuleBase)
{
	if (Module.empty())
		throw std::exception("DecryptVACIn: Module is empty");

	if (VacIn.empty())
		throw std::exception("DecryptVACIn: VacIn is empty");

	//Load VAC_8600.dll for encryption
	auto EncryptionModule = LoadLibraryA("C:/VAC_8600.dll");

	if (EncryptionModule == nullptr)
		throw std::exception("DecryptVACIn: Cannot load EncryptionModule");


	//Search for encryption function
	using InitializeEncryptionTablesType = int(*__cdecl)(unsigned char *VacInputOffset16, unsigned char *Out, int Size, unsigned char *Table);
	InitializeEncryptionTablesType InitializeEncryptionTables = nullptr;

	InitializeEncryptionTables = (InitializeEncryptionTablesType)FindPattern((DWORD)EncryptionModule, 0x4000, (BYTE*)"\x55\x8B\xEC\x83\xEC\x0C\x8D", "xxxxxxx", 0);

	if (InitializeEncryptionTables == nullptr)
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACIn: Cannot resolve encryption");
	}

	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)Module.data();
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	if (ntHeader->FileHeader.NumberOfSections < 3)
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACIn: Invalid NumberOfSections");
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
		FreeLibrary(EncryptionModule);
		throw std::exception("Cannot find section");
	}

	auto dataSectionPtr = (((unsigned long)ModuleBase) + pSecHeader->VirtualAddress);

	//Find all XorTables
	std::vector<ProcStruct*> ProcTable;
	unsigned long PatternResult = 0;

	do
	{
		PatternResult = FindPattern(dataSectionPtr, 0x200 + (ProcTable.size() * 0x200), (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "????????xxxx????????????????????????????????????xxxx", ProcTable.size());

		if (PatternResult)
		{
			ProcTable.push_back((ProcStruct*)PatternResult);

			if (ProcTable.size() >= PROC_LIMIT)
				break;
		}

	} while (PatternResult != 0);

	//Find the right one
	unsigned long* xorTable = nullptr;

	if (ProcTable.empty())
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACIn: ProcTable is empty");
	}

	for (auto Proc : ProcTable)
	{
		unsigned long VACChecksum1 = *(unsigned long*)VacIn.data();
		unsigned long VACChecksum2 = *(unsigned long*)(VacIn.data() + 0x4);

		if (Proc->Checksum1 == VACChecksum1 && Proc->Checksum2 == VACChecksum2)
		{
			xorTable = &Proc->XorTable;
			break;
		}
	}

	if (xorTable == nullptr)
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACIn: Cannot locate XorTable");
	}

	std::vector<unsigned char> Decrypted;
	Decrypted.resize(VacIn.size() - 16);

	InitializeEncryptionTables((unsigned char*)VacIn.data() + 16, (unsigned char*)Decrypted.data(), Decrypted.size(), (unsigned char*)xorTable);

	FreeLibrary(EncryptionModule);
	return Decrypted;
}

/**
 * Encrypts VAC Data
 * / throws dunno a few exceptions on error maybe ?
*/
__declspec(dllexport) std::vector<unsigned char> __stdcall EncryptVACData(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, const std::vector<unsigned char> &Decrypted, unsigned long ModuleBase, bool doXor)
{
	if (Module.empty())
		throw std::exception("EncryptVACData: Module is empty");

	if(VacIn.empty())
		throw std::exception("EncryptVACData: VacIn is empty");

	if (Decrypted.empty())
		throw std::exception("EncryptVACData: Encrypted data is empty");

	//Load VAC_8600.dll for encryption
	auto EncryptionModule = LoadLibraryA("C:/VAC_8600.dll");

	if (EncryptionModule == nullptr)
		throw std::exception("EncryptVACData: Cannot load EncryptionModule");


	//Search for encryption function
	using EncryptVACOutType = int(*__cdecl)(unsigned char *Address, unsigned char *Out, int Size, unsigned char *Table);
	using InitializeEncryptionTablesType = int(*__cdecl)(unsigned char *VacInputOffset16, unsigned char *Out, int Size, unsigned char *Table);
	
	InitializeEncryptionTablesType InitializeEncryptionTables = nullptr;
	EncryptVACOutType EncryptVACOut = nullptr;

	InitializeEncryptionTables = (InitializeEncryptionTablesType)FindPattern((DWORD)EncryptionModule, 0x4000, (BYTE*)"\x55\x8B\xEC\x83\xEC\x0C\x8D", "xxxxxxx", 0);
	EncryptVACOut = (EncryptVACOutType)FindPattern((DWORD)EncryptionModule, 0x4000, (BYTE*)"\x55\x8B\xEC\x83\xEC\x0C\x8D", "xxxxxxx", 1);

	if (EncryptVACOut == nullptr || InitializeEncryptionTables == nullptr)
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("EncryptVACData: Cannot resolve encryption");
	}

	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)Module.data();
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	if (ntHeader->FileHeader.NumberOfSections < 3)
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("DecryptVACData: Invalid NumberOfSections");
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
		FreeLibrary(EncryptionModule);
		throw std::exception("Cannot find section");
	}

	auto dataSectionPtr = (((unsigned long)ModuleBase) + pSecHeader->VirtualAddress);

	//Find all XorTables
	std::vector<ProcStruct*> ProcTable;
	unsigned long PatternResult = 0;

	do
	{
		PatternResult = FindPattern(dataSectionPtr, 0x200 + (ProcTable.size() * 0x200), (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "????????xxxx????????????????????????????????????xxxx", ProcTable.size());

		if (PatternResult)
		{
			ProcTable.push_back((ProcStruct*)PatternResult);

			if (ProcTable.size() >= PROC_LIMIT)
				break;
		}

	} while (PatternResult != 0);

	//Find the right one
	unsigned long* xorTable = nullptr;

	if (ProcTable.empty())
	{
		FreeLibrary(EncryptionModule);
		throw std::exception("EncryptVACData: ProcTable is empty");
	}

	for (auto Proc : ProcTable)
	{
		unsigned long VACChecksum1 = *(unsigned long*)VacIn.data();
		unsigned long VACChecksum2 = *(unsigned long*)(VacIn.data() + 0x4);

		char buf[500];
		sprintf_s(buf, 500, "ProcCheck: %X\0", Proc->Checksum1);
		std::cout << buf << std::endl;

		if (Proc->Checksum1 == VACChecksum1 && Proc->Checksum2 == VACChecksum2)
		{
			xorTable = &Proc->XorTable;
			break;
		}
	}

	if (xorTable == nullptr)
	{
		FreeLibrary(EncryptionModule);

		char buf[33];
		sprintf_s(buf, 32, "0x%X\0", *(unsigned long*)VacIn.data());
		throw std::exception((std::string("EncryptVACData: Cannot locate XorTable: ") + buf).c_str());
	}

	unsigned int GeneratedTable[44];
	InitializeEncryptionTables((unsigned char*)VacIn.data() + 16, (unsigned char*)GeneratedTable, sizeof(GeneratedTable), (unsigned char*)xorTable);

	auto xorKey = GeneratedTable[25];

	if (doXor)
	{
		//Encrypt XOR
		for (int i = 0; i < (Decrypted.size() - 12) / 4; ++i)
			((int*)Decrypted.data())[i + 3] ^= xorKey;
	}

	//Encrypt
	std::vector<unsigned char> Encrypted;
	Encrypted.resize(Decrypted.size());
	EncryptVACOut((unsigned char*)Decrypted.data(), Encrypted.data(), Encrypted.size(), ((unsigned char*)GeneratedTable) + 0x10);

	FreeLibrary(EncryptionModule);

	return Encrypted;
}

/**
 * Returns the checksum for the requested process function
 * /returns -1 on error and throws exception
*/
__declspec(dllexport) unsigned long __stdcall GetVACProcChecksum(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, unsigned long ModuleBase)
{
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

	auto dataSectionPtr = (((unsigned long)ModuleBase) + pSecHeader->VirtualAddress);;

	//Find all XorTables
	std::vector<ProcStruct*> ProcTable;
	unsigned long PatternResult = dataSectionPtr;

	do
	{
		PatternResult = FindPattern(dataSectionPtr, 0x200, (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "xxxx????xxxx????????????????????????????????????xxxx", ProcTable.size());

		if (PatternResult)
		{
			ProcTable.push_back((ProcStruct*)PatternResult);

			if (ProcTable.size() >= PROC_LIMIT)
				break;
		}
	} while (PatternResult);

	//Find the right one
	if (ProcTable.empty())
	{
		throw std::exception("ProcTable is empty");
		return -1;
	}

	for (auto Proc : ProcTable)
	{
		unsigned long VACChecksum1 = *(unsigned long*)VacIn.data();
		unsigned long VACChecksum2 = *(unsigned long*)(VacIn.data() + 0x4);

		if (Proc->Checksum1 == VACChecksum1 && Proc->Checksum2 == VACChecksum2)
			return Proc->Checksum1;
	}

	return -1;
}

/**
 * Returns all ProcAnalyze functions
 * /throws dunno a few exceptions on error
*/
__declspec(dllexport) std::vector<ProcStruct*> GetVACProcedures(const std::vector<unsigned char> &Module, unsigned long ModuleBase)
{
	if (Module.empty())
		throw std::exception("Module is empty");

	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)Module.data();
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	if (ntHeader->FileHeader.NumberOfSections < 3)
		throw std::exception("Invalid NumberOfSections");

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

	auto dataSectionPtr = (((unsigned long)ModuleBase) + pSecHeader->VirtualAddress);

	//Find all Procs
	std::vector<ProcStruct*> ProcTable;
	unsigned long PatternResult = dataSectionPtr;

	do
	{
		PatternResult = FindPattern(dataSectionPtr, 0x200, (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "xxxx????xxxx????????????????????????????????????xxxx", ProcTable.size());

		if (PatternResult)
		{
			ProcTable.push_back((ProcStruct*)PatternResult);

			if (ProcTable.size() >= PROC_LIMIT)
				break;
		}
	} while (PatternResult);
}

__declspec(dllexport) ProcStruct* __stdcall GetVACProcChecksumProc(unsigned char *Module, const std::vector<unsigned char> &VacIn, unsigned long ModuleBase)
{
	if (Module == nullptr)
	{
		throw std::exception("Module is empty");
		return nullptr;
	}

	if (VacIn.empty())
	{
		throw std::exception("VacIn is empty");
		return nullptr;
	}

	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)Module;
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	if (ntHeader->FileHeader.NumberOfSections < 3)
	{
		throw std::exception("Invalid NumberOfSections");
		return nullptr;
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

	auto dataSectionPtr = (((unsigned long)ModuleBase) + pSecHeader->VirtualAddress);

	//Find all XorTables
	std::vector<ProcStruct*> ProcTable;
	unsigned long PatternResult = dataSectionPtr;

	do
	{
		PatternResult = FindPattern(dataSectionPtr, pSecHeader->SizeOfRawData, (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "xxxx????xxxx????????????????????????????????????xxxx", ProcTable.size());

		if (PatternResult)
		{
			ProcTable.push_back((ProcStruct*)PatternResult);

			if (ProcTable.size() >= PROC_LIMIT)
				break;
		}
	} while (PatternResult);

	//Find the right one
	if (ProcTable.empty())
	{
		throw std::exception("ProcTable is empty");
		return nullptr;
	}

	for (auto Proc : ProcTable)
	{
		unsigned long VACChecksum1 = *(unsigned long*)VacIn.data();
		unsigned long VACChecksum2 = *(unsigned long*)(VacIn.data() + 0x4);

		char buf[1000];
		sprintf_s(buf, "VACChecksum1: 0x%X\nVACChecksum2: 0x%X\nNextProc: 0x%X\nChecksum1: 0x%X\nChecksum2: 0x%X\nProcAddress: 0x%X\nXorTable: 0x%X", VACChecksum1, VACChecksum2, Proc->NextProc, Proc->Checksum1, Proc->Checksum2, Proc->ProcAddress, Proc->XorTable);
		std::cout << buf << std::endl;

		if (Proc->Checksum1 == VACChecksum1/* && Proc->Checksum2 == VACChecksum2*/)
			return Proc;
	}

	return nullptr;
}