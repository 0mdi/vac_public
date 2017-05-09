/*
	Created by Omdihar
*/
#include <Windows.h>
#include <fstream>


//@DwStatus
extern "C" __declspec(dllexport) int __stdcall DwStatus(int *exit_code_ptr)
{
	int tmp_status = 0x00000000 & 0xFFFF003F | 0x30;

	if (exit_code_ptr == (int*)259)
		tmp_status = tmp_status | 3;
	else
		tmp_status = (tmp_status | 1) & 0xFFFFFFFD;

	*exit_code_ptr = tmp_status;

	return tmp_status;
}

//@Enter3
extern "C" __declspec(dllexport) int __cdecl Enter3()
{
	return 0;
}

//@Shutdown
extern "C" __declspec(dllexport) void __cdecl Shutdown()
{
	return;
}

//@Startup2
extern "C" __declspec(dllexport) bool __cdecl Startup2(HANDLE named_pipe, HANDLE file, HANDLE handle, HANDLE event)
{
	return true;
}

//@Startup3
extern "C" __declspec(dllexport) bool __cdecl Startup3(HANDLE named_pipe, HANDLE file, HANDLE handle, HANDLE event)
{
	return true;
}

//@StartupData
extern "C" __declspec(dllexport) void* __cdecl StartupData(HANDLE thread)
{
	return thread;
}

//DllEntryPoint
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	return true;
}