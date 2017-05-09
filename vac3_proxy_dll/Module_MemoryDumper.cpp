/*
ProcessID = *(_DWORD *)(VacIn + 96)
BaseAddr = *(_DWORD *)(VacIn + 100)
BaseAddrMax = *(_DWORD *)(VacIn + 104)
MaxRegionSize = *(_DWORD *)(VacIn + 108)
ReadMemCmd = *(_DWORD *)(VacIn + 112) != 0;
*/

#include "Module_MemoryDumper.hpp"
#include "ModuleUtils.hpp"

#include <Windows.h>
#include <string>

#include <iostream>

typedef NTSTATUS(__stdcall *ZwQueryVirtualMemory_t)(HANDLE, PVOID, int, PVOID, SIZE_T, PSIZE_T);

struct UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR    Buffer;
};

bool Module_MemoryDumper::Preprocess(const std::vector<unsigned char>& ModuleVec, unsigned long ModuleBase, unsigned char *VacParam, unsigned char *VacOut, unsigned long *VacOutSizePtr)
{
	//VACProc0: Use NtQueryVirtualMemory and find out if they are scanning one of my modules
	//VACProc1: ???
	std::cout << "Getting index" << std::endl;

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacParam, VacParam + 0xB0 }, ModuleBase);
	std::cout << "index: " << index << std::endl;

	if (index != 0 && index != 1)
		throw std::exception("Unknown proc index");

	auto ProcessID = *(uint32_t*)(VacParam + 96);
	auto BaseAddr = *(uint32_t*)(VacParam + 100);

	std::cout << "ProcessID: 0x" << std::hex << ProcessID << std::endl;
	std::cout << "BaseAddr: 0x" << std::hex << BaseAddr << std::endl;

	auto ZwQueryVirtualMemory = (ZwQueryVirtualMemory_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwQueryVirtualMemory");

	if (!ZwQueryVirtualMemory)
	{
		MessageBoxA(nullptr, "ZwQueryVirtualMemory not resolved - OmdisCheats", "OmdisCheats Error", MB_TOPMOST);
	}

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);

	if (!hProcess)
	{
		std::cout << "Cannot OpenProcess!" << std::endl;
		return false;
	}

	char Buffer[MAX_PATH * 2 + 4] = { 0 };
	auto Ret = ZwQueryVirtualMemory(hProcess, (void*)BaseAddr, 1, Buffer, sizeof(Buffer), 0);
	std::cout << "Ret: 0x" << std::hex << Ret << std::endl;

	if (Ret < 0)
		return false;

	std::wstring wstr = ((UNICODE_STRING*)Buffer)->Buffer;
	MessageBoxW(nullptr, wstr.c_str(), L"OmdisCheats Preprocess", MB_TOPMOST);
	if (wstr.find(L"cheat_files") != std::wstring::npos || wstr.find(L"omdis_cheats") != std::wstring::npos)
	{
		//One of our modules maaaan, hide that shit
		//Emulate that we failed to decrypt VAC API
		*VacOutSizePtr = 4096; 
		*(uint32_t*)(VacOut + 16) = 78;
		return true;
	}

	std::cout << "End Preprocessing!" << std::endl;
	return false;
}