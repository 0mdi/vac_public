#include "Preprocessor.hpp"
#include "Hash.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <fstream>
#include <algorithm>

#include "detours.h"

#include "Module_MemoryDumper.hpp"

/* WINDOW STUFF */
typedef BOOL(__stdcall *EnumWindowsType)(WNDENUMPROC, LPARAM);
typedef BOOL(__stdcall *EnumChildWindowsType)(HWND, WNDENUMPROC, LPARAM);

WNDENUMPROC WindowsProcOrig = nullptr;
WNDENUMPROC ChildProcOrig = nullptr;

EnumWindowsType EnumWindowsOrig = nullptr;
EnumChildWindowsType EnumChildWindowsOrig = nullptr;

bool IsDangerous(HWND hWnd)
{
	char WindowTitle[1024];

	auto WindowTitleLength = GetWindowTextA(hWnd, WindowTitle, 1024);
	auto strWindowTitle = std::string(WindowTitle);

	if (WindowTitleLength && (strWindowTitle.find("Cheat") != std::string::npos || strWindowTitle.find("Omdi") != std::string::npos))
	{
		//MessageBoxA(nullptr, "Bad Window", WindowTitle, MB_TOPMOST);
		return true;
	}

	return false;
}

signed int __stdcall ChildProcHook(HWND hWnd, LPARAM lParam)
{
	if (IsDangerous(hWnd))
		return 1;

	return ChildProcOrig(hWnd, lParam);
}

signed int __stdcall WindowsProcHook(HWND hWnd, LPARAM lParam)
{
	if (IsDangerous(hWnd))
		return 1;

	return WindowsProcOrig(hWnd, lParam);
}

BOOL __stdcall EnumChildWindowsHook(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
	ChildProcOrig = lpEnumFunc;
	return EnumChildWindowsOrig(hWndParent, ChildProcHook, lParam);
}

BOOL __stdcall EnumWindowsHook(WNDENUMPROC lpEnumFunc, LPARAM lParam)
{
	WindowsProcOrig = lpEnumFunc;
	return EnumWindowsOrig(WindowsProcHook, lParam);
}

/*DUMP STUFF*/
typedef int(__fastcall *HashString_t)(char*, int);
HashString_t HashStringOrig = nullptr;

typedef BOOL(__stdcall *EnumProcesses_t)(DWORD*, DWORD, DWORD*);
EnumProcesses_t EnumProcessesOrig = nullptr;

typedef BOOL(__stdcall *Process32First_t)(HANDLE, LPPROCESSENTRY32);
Process32First_t Process32FirstOrig = nullptr;

typedef BOOL(__stdcall *Process32Next_t)(HANDLE, LPPROCESSENTRY32);
Process32Next_t Process32NextOrig = nullptr;

typedef BOOL(__stdcall *Module32First_t)(HANDLE, LPMODULEENTRY32);
Module32First_t Module32FirstOrig = nullptr;

typedef BOOL(__stdcall *Module32Next_t)(HANDLE, LPMODULEENTRY32);
Module32Next_t Module32NextOrig = nullptr;

typedef HANDLE(__stdcall *CreateFileA_t)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileA_t CreateFileAOrig = nullptr;

typedef NTSTATUS(__stdcall *ZwQueryVirtualMemory_t)(HANDLE, PVOID, int, PVOID, SIZE_T, PSIZE_T);
ZwQueryVirtualMemory_t ZwQueryVirtualMemoryOrig = nullptr;

typedef NTSTATUS(__stdcall *NtQuerySystemInformation_t)(ULONG SystemInfoClass, PVOID SystemInfo, ULONG SystemInfoLength, PULONG ReturnLength);
NtQuerySystemInformation_t NtQuerySystemInformationOrig = nullptr;

struct UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR    Buffer;
};

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount; /* Or NumberOfHandles if you prefer. */
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef UNICODE_STRING *PUNICODE_STRING;

bool _DataCompare(const BYTE* OpCodes, const BYTE* Mask, const char* StrMask)
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

DWORD _FindPattern(DWORD StartAddress, DWORD CodeLen, BYTE* Mask, char* StrMask, unsigned short ignore)
{
	unsigned short Ign = 0;
	DWORD i = 0;

	while (Ign <= ignore)
	{
		if (_DataCompare((BYTE*)(StartAddress + i++), Mask, StrMask))
			++Ign;

		else if (i >= CodeLen)
			return 0;
	}

	return StartAddress + i - 1;
}

std::string BlacklistProcessName[] =
{
	"omdis",
	"OmdisCheats",
	"csgo_hack",
	"idaq.exe",
	"cheatengine-i386.exe",
	"UnknownInject.exe",
	"ocs",
	"Local\Temp",
	"HazeDumper",
	"Wireshark.exe",
	"AntTweakBar",
	"lua5.1",
	"luabind",
	"cheat_files",
	"VMProtect"
};

bool CheckStringDangerous(unsigned char *VacOut, unsigned long *VacOutSize)
{
	//Loop through BlacklistProcessName
	for (auto blacklisted : BlacklistProcessName)
	{
		std::string mask;

		for (int i = 0; i < blacklisted.length(); ++i)
			mask += 'x';

		auto it = _FindPattern((unsigned long)VacOut, *VacOutSize, (unsigned char*)blacklisted.c_str(), (char*)mask.c_str(), 0);

		if (it)
			return true;
	}
	return false;
}

int __fastcall HashStringHook(char *String, int Length)
{
	/*static std::ofstream* log_file = nullptr;

	if(!log_file)
		log_file = new std::ofstream("C:/hash_log.omdis");

	*log_file << std::string(String, Length) << std::endl;*/
	//MessageBoxA(nullptr, String, "OmdisCheats", MB_TOPMOST);

	if(CheckStringDangerous((unsigned char*)String, (unsigned long*)&Length))
	{
		//MessageBoxA(nullptr, String, "Badboy", MB_TOPMOST);
		return 0xDEADBEEF;
	}

	if (HashStringOrig == nullptr)
		MessageBoxW(nullptr, L"HashStringOrig is nullptr", L"Error", MB_TOPMOST);

	return HashStringOrig(String, Length);
}

BOOL __stdcall EnumProcessesHook(DWORD *pProcessIds, DWORD cb, DWORD *pBytesReturned)
{
	if(EnumProcessesOrig == nullptr)
		MessageBoxW(nullptr, L"EnumProcessesOrig is nullptr", L"Error", MB_TOPMOST);

	auto result = EnumProcessesOrig(pProcessIds, cb, pBytesReturned);

	if (!result)
		return result;

	DWORD NewList[500];
	int ListSize = 0;
	memset(NewList, 0, sizeof(NewList));
	for (int i = 0; i < *pBytesReturned / 4; ++i)
	{
		auto ProcessId = pProcessIds[i];

		auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, ProcessId);

		if (hProcess && hProcess != INVALID_HANDLE_VALUE)
		{
			char FileName[MAX_PATH];

			auto Length = GetProcessImageFileNameA(hProcess, FileName, MAX_PATH);

			if (Length != 0)
			{
				if (!CheckStringDangerous((unsigned char*)FileName, &Length))
				{
					NewList[ListSize] = ProcessId;
					++ListSize;
				}
				/*else
				{
					MessageBoxA(nullptr, FileName, "Blacklisted", MB_TOPMOST);
				}*/
			}
		}
	}

	*pBytesReturned = ListSize * 4;
	memset(pProcessIds, 0, cb);
	memcpy(pProcessIds, NewList, ListSize * 4);

	return result;
}

bool IsProcessDangerous(LPPROCESSENTRY32 lppe)
{
	auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, lppe->th32ProcessID);

	if (hProcess && hProcess != INVALID_HANDLE_VALUE)
	{
		char FileName[MAX_PATH];

		auto Length = GetProcessImageFileNameA(hProcess, FileName, MAX_PATH);

		if (Length != 0)
			return CheckStringDangerous((unsigned char*)FileName, &Length);
		else
			return true;
	}

	return true;
}

BOOL __stdcall Process32FirstHook(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
	if(Process32FirstOrig == nullptr)
		MessageBoxW(nullptr, L"Process32FirstOrig is nullptr", L"Error", MB_TOPMOST);

	bool dangerous = true;
	auto result = Process32FirstOrig(hSnapshot, lppe);;

	if (!result)
		return false;

	if (!IsProcessDangerous(lppe))
		return result;

	while (dangerous)
	{
		result = Process32NextOrig(hSnapshot, lppe);

		if (!result)
			return false;

		dangerous = IsProcessDangerous(lppe);
	}

	return result;
}

BOOL __stdcall Process32NextHook(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
	if (Process32NextOrig == nullptr)
		MessageBoxW(nullptr, L"Process32NextOrig is nullptr", L"Error", MB_TOPMOST);

	bool dangerous = true;
	BOOL result = true;

	while (dangerous)
	{
		result = Process32NextOrig(hSnapshot, lppe);

		if (!result)
			return false;

		dangerous = IsProcessDangerous(lppe);
	}

	return result;
}

bool IsModuleDangerous(LPMODULEENTRY32 lpme)
{
	char ModuleName[MAX_PATH];
	auto Length1 = wcstombs(ModuleName, lpme->szModule, MAX_PATH);

	char ExeName[MAX_PATH];
	auto Length2 = wcstombs(ExeName, lpme->szExePath, MAX_PATH);

	if (!Length1 || !Length2)
		return true;

	auto result1 = CheckStringDangerous((unsigned char*)ModuleName, (unsigned long*)&Length1);
	auto result2 = CheckStringDangerous((unsigned char*)ExeName, (unsigned long*)&Length2);

	return result1 || result2;
}

BOOL __stdcall Module32FirstHook(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
{
	if (Module32FirstOrig == nullptr)
		MessageBoxW(nullptr, L"Module32FirstOrig == nullptr", L"Error", MB_TOPMOST);

	bool dangerous = true;
	auto result = Module32FirstOrig(hSnapshot, lpme);;

	if (!result)
		return false;

	if (!IsModuleDangerous(lpme))
		return result;

	while (dangerous)
	{
		result = Module32NextOrig(hSnapshot, lpme);

		if (!result)
			return false;

		dangerous = IsModuleDangerous(lpme);
	}

	return result;
}

BOOL __stdcall Module32NextHook(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
{
	if (Module32NextOrig == nullptr)
		MessageBoxW(nullptr, L"Module32NextOrig == nullptr", L"Error", MB_TOPMOST);


	bool dangerous = true;
	BOOL result = true;

	while (dangerous)
	{
		result = Module32NextOrig(hSnapshot, lpme);

		if (!result)
			return false;

		dangerous = IsModuleDangerous(lpme);
	}

	return result;
}

HANDLE __stdcall CreateFileAHook(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	auto size = strlen((char*)lpFileName);
	if (CheckStringDangerous((unsigned char*)lpFileName, (unsigned long*)&size))
	{
		SetLastError(ERROR_ACCESS_DENIED);
		return (HANDLE)-1;
	}

	return CreateFileAOrig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
		dwFlagsAndAttributes, hTemplateFile);
}

NTSTATUS __stdcall ZwQueryVirtualMemoryHook(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass,
	PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
	auto ret = ZwQueryVirtualMemoryOrig(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation,
		MemoryInformationLength, ReturnLength);

	if (MemoryInformationClass == 1)
	{
		std::wstring wstr = ((PUNICODE_STRING)MemoryInformation)->Buffer;

		if (wstr.find(L"cheat_files") != std::wstring::npos || wstr.find(L"omdis_cheats") != std::wstring::npos)
		{
			memset(MemoryInformation, 0, MemoryInformationLength);
			SetLastError(ERROR_ACCESS_DENIED);
			return 0xC0000022; //STATUS_ACCESS_DENIED
		}
	}

	return ret;
}

NTSTATUS __stdcall NtQuerySystemInformationHook(ULONG SystemInfoClass, PVOID SystemInfo, ULONG SystemInfoLength, PULONG ReturnLength)
{
	auto ret = NtQuerySystemInformationOrig(SystemInfoClass, SystemInfo, SystemInfoLength, ReturnLength);

	if (SystemInfoClass == 16 && ret >= 0)
	{
		auto HandleInfo = (SYSTEM_HANDLE_INFORMATION*)SystemInfo;

		for (int i = 0; i < HandleInfo->HandleCount; ++i)
		{
			auto Handle = &HandleInfo->Handles[i];

			auto processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, Handle->ProcessId);

			if (processHandle != 0)
			{
				char Name[MAX_PATH];
				auto size = GetProcessImageFileNameA(processHandle, Name, MAX_PATH);
				
				if (CheckStringDangerous((unsigned char*)Name, &size) || Handle->Flags == 0x0012019f)
				{
					//MessageBoxA(nullptr, Name, "Handle Removing...", MB_TOPMOST);
					memset(Handle, 0, sizeof(SYSTEM_HANDLE));
					/*--HandleInfo->HandleCount;
					std::copy(&HandleInfo->Handles[i + 1], &HandleInfo->Handles[HandleInfo->HandleCount], &HandleInfo->Handles[i]);
					memset(&HandleInfo->Handles[HandleInfo->HandleCount + 1], 0, sizeof(SYSTEM_HANDLE));*/
				}
			}
		}
	}
	else if (SystemInfoClass == 5 && ret >= 0)
	{
		auto SystemProcess = (SYSTEM_PROCESS_INFO*)SystemInfo;

		auto NextSystemProcess = (SYSTEM_PROCESS_INFO*)((LPBYTE)SystemProcess + SystemProcess->NextEntryOffset);

		while (NextSystemProcess->NextEntryOffset != 0)
		{
			char pName[256];
			memset(pName, 0, sizeof(pName));
			WideCharToMultiByte(CP_ACP, 0, NextSystemProcess->ImageName.Buffer, NextSystemProcess->ImageName.Length, pName, sizeof(pName), NULL, NULL);
			auto size = strlen(pName);

			if (CheckStringDangerous((unsigned char*)pName, (unsigned long*)&size))
			{
				//MessageBoxA(nullptr, pName, "Process Removing...", MB_TOPMOST);
				SystemProcess->NextEntryOffset += NextSystemProcess->NextEntryOffset;
			}

			SystemProcess = NextSystemProcess;
			NextSystemProcess = (SYSTEM_PROCESS_INFO*)((LPBYTE)SystemProcess + SystemProcess->NextEntryOffset);
		}
	}

	return ret;
}

/*PREPROCESSOR*/
bool Preprocessor::PreprocessBegin(const std::vector<unsigned char>& ModuleVec, unsigned long ModuleBase, unsigned char *VacParam, unsigned char *VacOut, unsigned long *VacOutSizePtr)
{
	bool Preprocessed = false;

	if (ModuleVec.empty())
		return false;

	auto hash = str2int(HashPEHeader((unsigned char*)ModuleVec.data()).data());

	switch (hash)
	{
	//Memory Dumper
	/*case str2int("ad37327cc2215d1e8a8e7bff9d2ce276"):
		try
		{
			Preprocessed = Module_MemoryDumper::Preprocess(ModuleVec, ModuleBase, VacParam, VacOut, VacOutSizePtr);
		}
		catch (const std::exception& e)
		{
			MessageBoxA(nullptr, e.what(), "OmdisCheats Exception", MB_TOPMOST);
		}
		break;*/

	//Window Module
	case str2int("8d950d606675e1ad21fa5d51cc8dfbf2"):
	case str2int("8c166437ff9327e7081b97c2808ff6d9"):
	case str2int("92378b5671a0387705da0defdd7dd5fc"): //26.11.2016
		//Hook EnumWindows
		EnumWindowsOrig = (EnumWindowsType)DetourFunction((unsigned char*)EnumWindows, (unsigned char*)EnumWindowsHook);
		EnumChildWindowsOrig = (EnumChildWindowsType)DetourFunction((unsigned char*)EnumChildWindows, (unsigned char*)EnumChildWindowsHook);
		break;

	//Process & DLL Module
	case str2int("022d25958e1077aea01e9e47187ec713"):
	case str2int("44eb01e6f227fa894807169cf2d47377"):
	case str2int("93029e08f4309c4aa2bd364f449f6fe0"):
	case str2int("8f5e338c235fb79f99c123c2bfc35b89"): // 09.11.2016
	case str2int("84ad052e2ee1922e6e5294a58a00a906"): // 09.11.2016
		//MessageBoxA(nullptr, "Debug Here", "OmdisCheats", MB_TOPMOST);
	case str2int("adf055372fac36860e2faf1503343d3a"): //17.11.2016
	case str2int("99ab1432269a92b5b813fc95905cf550"): //26.11.2016
	case str2int("9d1b58e5b25a10b7e6a5605e12db5dc8"): //13.03.2016

		//Patch it because it gets stuck
		if (hash == str2int("adf055372fac36860e2faf1503343d3a"))
		{
			unsigned long OldProtect = 0;
			VirtualProtect((void*)(ModuleBase + 0x1E12), 1, PAGE_EXECUTE_READWRITE, &OldProtect);
			*(unsigned char*)(ModuleBase + 0x1E12) = 0xEB;
			VirtualProtect((void*)(ModuleBase + 0x1E12), 1, OldProtect, &OldProtect);
		}

		auto addr = (unsigned char*)_FindPattern(ModuleBase, 0x9000, (unsigned char*)"\xB8\x92\x18\xD7\x45\x85\xD2", "xxxxxxx", 0);

		if (addr == nullptr)
		{
			MessageBoxA(nullptr, "addr not found", "Error", MB_TOPMOST);
		}

		//Hook it now
		HashStringOrig = (HashString_t)DetourFunction((unsigned char*)addr, (unsigned char*)HashStringHook);

		//auto EnumProcessesAddr = (unsigned char*)GetProcAddress(GetModuleHandleA("KERNELBASE.dll"), "EnumProcesses");

		//if(EnumProcessesAddr)
		//	EnumProcessesOrig = (EnumProcesses_t)DetourFunction((unsigned char*)EnumProcessesAddr, (unsigned char*)EnumProcessesHook);

		Process32FirstOrig = (Process32First_t)DetourFunction((unsigned char*)Process32First, (unsigned char*)Process32FirstHook);
		Process32NextOrig = (Process32Next_t)DetourFunction((unsigned char*)Process32Next, (unsigned char*)Process32NextHook);
		Module32FirstOrig = (Module32First_t)DetourFunction((unsigned char*)Module32First, (unsigned char*)Module32FirstHook);
		Module32NextOrig = (Module32Next_t)DetourFunction((unsigned char*)Module32Next, (unsigned char*)Module32NextHook);
		CreateFileAOrig = (CreateFileA_t)DetourFunction((unsigned char*)CreateFileA, (unsigned char*)CreateFileAHook);

		auto ZwQueryVirtualMemoryAddr = (unsigned char*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryVirtualMemory");

		if(ZwQueryVirtualMemoryAddr)
			ZwQueryVirtualMemoryOrig = (ZwQueryVirtualMemory_t)DetourFunction(ZwQueryVirtualMemoryAddr, (unsigned char*)ZwQueryVirtualMemoryHook);

		auto NtQuerySystemInformationAddr = (unsigned char*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

		if (NtQuerySystemInformationAddr)
			NtQuerySystemInformationOrig = (NtQuerySystemInformation_t)DetourFunction(NtQuerySystemInformationAddr, (unsigned char*)NtQuerySystemInformationHook);

		if (!HashStringOrig || /*!EnumProcessesOrig ||*/ !Process32FirstOrig || !Process32NextOrig || !Module32FirstOrig || !Module32NextOrig || !CreateFileAOrig || !ZwQueryVirtualMemoryOrig || !NtQuerySystemInformationOrig)
		{
			MessageBoxA(nullptr, "Cheat will shutdown due to safety reasons", "OmdisCheats Safety Error", MB_TOPMOST);
			exit(-1);
		}

		break;
	}

	return Preprocessed;
}

void Preprocessor::PreprocessEnd(const std::vector<unsigned char>& ModuleVec)
{
	auto hash = str2int(HashPEHeader((unsigned char*)ModuleVec.data()).data());

	switch (hash)
	{
	//Window Module
	case str2int("8d950d606675e1ad21fa5d51cc8dfbf2"):
	case str2int("8c166437ff9327e7081b97c2808ff6d9"):
	case str2int("92378b5671a0387705da0defdd7dd5fc"): //26.11.2016
		DetourRemove((unsigned char*)EnumWindowsOrig, (unsigned char*)EnumWindowsHook);
		DetourRemove((unsigned char*)EnumChildWindowsOrig, (unsigned char*)EnumChildWindowsHook);
		break;

	//Process & DLL Module
	case str2int("022d25958e1077aea01e9e47187ec713"):
	case str2int("44eb01e6f227fa894807169cf2d47377"):
	case str2int("93029e08f4309c4aa2bd364f449f6fe0"):
	case str2int("8f5e338c235fb79f99c123c2bfc35b89"): // 09.11.2016
	case str2int("84ad052e2ee1922e6e5294a58a00a906"): // 09.11.2016
	case str2int("adf055372fac36860e2faf1503343d3a"): //17.11.2016
	case str2int("99ab1432269a92b5b813fc95905cf550"): //26.11.2016

		if (HashStringOrig)
		{
			DetourRemove((PBYTE)HashStringOrig, (PBYTE)HashStringHook);
			HashStringOrig = nullptr;
		}

		//if (EnumProcessesOrig)
		//{
		//	DetourRemove((PBYTE)EnumProcessesOrig, (PBYTE)EnumProcessesHook);
		//	EnumProcessesOrig = nullptr;
		//}

		if (Process32FirstOrig)
		{
			DetourRemove((PBYTE)Process32FirstOrig, (PBYTE)Process32FirstHook);
			Process32FirstOrig = nullptr;
		}

		if (Process32NextOrig)
		{
			DetourRemove((PBYTE)Process32NextOrig, (PBYTE)Process32NextHook);
			Process32NextOrig = nullptr;
		}

		if (Module32FirstOrig)
		{
			DetourRemove((PBYTE)Module32FirstOrig, (PBYTE)Module32FirstHook);
			Module32FirstOrig = nullptr;
		}

		if (Module32NextOrig)
		{
			DetourRemove((PBYTE)Module32NextOrig, (PBYTE)Module32NextHook);
			Module32NextOrig = nullptr;
		}

		if (CreateFileAOrig)
		{
			DetourRemove((PBYTE)CreateFileAOrig, (PBYTE)CreateFileAHook);
			CreateFileAOrig = nullptr;
		}

		if (ZwQueryVirtualMemoryOrig)
		{
			DetourRemove((PBYTE)ZwQueryVirtualMemoryOrig, (PBYTE)ZwQueryVirtualMemoryHook);
			ZwQueryVirtualMemoryOrig = nullptr;
		}

		if (NtQuerySystemInformationOrig)
		{
			DetourRemove((PBYTE)NtQuerySystemInformationOrig, (PBYTE)NtQuerySystemInformationHook);
			NtQuerySystemInformationOrig = nullptr;
		}

		break;
	}
}