#include <boost/array.hpp>
#include <boost/asio.hpp>

#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <algorithm>
#include <string>
#include <mutex>
#include <process.h>

#include <stdio.h>

#include "detours.h"

#include "proxy_protocol.hpp"
#include "proxy_client.hpp"

#include "xor_encryption.hpp"

#include "Breakpoint.h"

#include "../easylogging++.h"

#include "../vac3_proxy/MemoryModule.h"
#include "Preprocessor.hpp"
#include "ModuleUtils.hpp"

#include "Hash.hpp"

#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "detours.lib")

#define PROXY_IP "127.0.0.1"

_INITIALIZE_EASYLOGGINGPP

//55 8B EC 56 8B 75 08 57 8B F9 83 7E 0C 00 LoadVAC3 Pattern
typedef char(__stdcall* load_vac3_type)(int module_struct, char unk);
load_vac3_type load_vac3_orig = nullptr;

typedef int(__stdcall*runfunc_t)(int, unsigned char*, int, unsigned char*, int*);
runfunc_t runfunc_orig = nullptr;

typedef int(__cdecl* ProcAnalyze_t)(unsigned char*, unsigned char*, unsigned long*);
ProcAnalyze_t procTrampoline = nullptr;
std::function<void(unsigned char*, unsigned long)> procLambda;

typedef signed int(__cdecl *VerifyModule_t)(unsigned char*, unsigned int, int, int);
VerifyModule_t VerifyModuleOrig = nullptr;

unsigned long hook_addr = 0;

std::wstring cheat_path;
proxy_client* client = nullptr;

boost::asio::io_service *g_service = nullptr;

std::vector<unsigned char> *ModuleVec = nullptr;

std::mutex g_mutex;

std::ofstream *log_file = nullptr;
std::wofstream *wlog_file = nullptr;

struct VACModule
{
	int field_0;
	HMODULE hModule;
	int pModule;
	runfunc_t runfunc_func_ptr;
	int last_error_code;
	int module_size;
	int module_data_ptr;
};

struct shared_info
{
	char session_key[33];
};

#define PROC_LIMIT 10

struct ProcStruct
{
	unsigned long NextProc;
	unsigned long Checksum1;
	unsigned long Checksum2;
	unsigned long ProcAddress;
	unsigned long XorTable;
};

int __cdecl atexit_hook(int)
{
	return true;
}

/**
* Returns the checksum for the requested process function
* /returns -1 on error and throws exception
*/
ProcStruct* __stdcall GetVACProcChecksumProc(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, HMODULE ModuleBase)
{
	if (Module.empty())
	{
		return nullptr;
	}

	if (VacIn.empty())
	{
		return nullptr;
	}

	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)Module.data();
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	if (ntHeader->FileHeader.NumberOfSections < 3)
	{
		return nullptr;
	}

	auto pSecHeader = IMAGE_FIRST_SECTION(ntHeader);
	bool foundSection = false;

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
	{
		pSecHeader = IMAGE_FIRST_SECTION(ntHeader) + i;
		//MessageBoxA(nullptr, (char*)pSecHeader->Name, "NAME", MB_TOPMOST);
		if (strcmp((char*)pSecHeader->Name, ".data") == 0)
		{
			foundSection = true;
			break;
		}
	}

	if (!foundSection)
	{
		return nullptr;
	}

	auto dataSectionPtr = (((unsigned long)ModuleBase) + pSecHeader->VirtualAddress);

	/*char buf[200];
	sprintf_s(buf, 200, "ModuleBase: 0x%X\ndataSectionPtr: 0x%X\nVirtualAddress: 0x%X", ModuleBase, dataSectionPtr, pSecHeader->VirtualAddress);
	MessageBoxA(nullptr, buf, "debug", MB_TOPMOST);*/

	//Find all XorTables
	std::vector<ProcStruct*> ProcTable;
	unsigned long PatternResult = dataSectionPtr;
	//unsigned long PatternResult = (unsigned long)Module.data();

	do
	{
		PatternResult = FindPattern(dataSectionPtr, pSecHeader->SizeOfRawData, (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "xxxx????xxxx????????????????????????????????????xxxx", ProcTable.size());

		//00 00 00 00 ? ? ? ? ? ? ? ? 01 00 00 00
		//PatternResult = FindPattern((unsigned long)Module.data() + 0x1000, Module.size() - 0x1000, (BYTE*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00", "xxxx????????xxxx", ProcTable.size());

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
		return nullptr;
	}

	for (auto Proc : ProcTable)
	{
		unsigned long VACChecksum1 = *(unsigned long*)VacIn.data();
		unsigned long VACChecksum2 = *(unsigned long*)(VacIn.data() + 0x4);

		/*char buf[1000];
		sprintf_s(buf, "NextProc: 0x%X\nChecksum1: 0x%X\nChecksum2: 0x%X\nProcAddress: 0x%X\nXorTable: 0x%X", Proc->NextProc, Proc->Checksum1, Proc->Checksum2, Proc->ProcAddress, Proc->XorTable);
		MessageBoxA(nullptr, buf, "LOL", MB_TOPMOST);*/

		if (Proc->Checksum1 == VACChecksum1/* && Proc->Checksum2 == VACChecksum2*/)
			return Proc;
	}

	return nullptr;
}

inline void panic_crash(int msg)
{
	//Call crash_handler.exe (in resource) later here
	std::string final_msg = "Something went wrong -> " + std::to_string(msg);
	MessageBoxA(0, final_msg.c_str(), "OmdisCheats", MB_TOPMOST);
	exit(0);
}

signed int __cdecl VerifyModuleHook(unsigned char *module_data, unsigned int module_size, int a3, int a4)
{
	//MessageBoxA(nullptr, "VerifyModule called", "debug", MB_TOPMOST);
	//MessageBoxA(nullptr, "VerifyModule", "", MB_TOPMOST);
	//Save module
	if (ModuleVec)
		delete ModuleVec;

	ModuleVec = new std::vector<unsigned char>{ (unsigned char*)module_data, (unsigned char*)module_data + module_size };

	return VerifyModuleOrig(module_data, module_size, a3, a4);
}

unsigned long vac_module = 0;
int __cdecl procHook(unsigned char *VacParam, unsigned char *VacOut, unsigned long *VacOutSizePtr)
{
	//Preprocess stuff
	auto Preprocessed = Preprocessor::PreprocessBegin(*ModuleVec, vac_module, VacParam, VacOut, VacOutSizePtr);

	//Module_MemoryDumper found one of our modules
	if (Preprocessed)
	{
		MessageBoxW(nullptr, L"Skipping Proc due to Preprocess", L"OmdisCheats", MB_TOPMOST);
		return 0;
	}

	auto ret = procTrampoline(VacParam, VacOut, VacOutSizePtr);

	//Stuff is not encrypted (exception: custom xor) but already processed
	//Tamper with it here and let the rest of the vac module handle the encryption hehe (SEND IT TO MY SERVER BIATCH)
	procLambda(VacOut, *VacOutSizePtr);

	//End Preporcess here
	Preprocessor::PreprocessEnd(*ModuleVec);

	return ret;
}

bool connect_to_server(proxy_client *client)
{
	bool server_connect_success = false;
	unsigned char server_connect_count = 0;

	while (!server_connect_success && server_connect_count < 10)
	{
		++server_connect_count;

		//Connect to server
		if (!client->connect(PROXY_IP, "1337"))
		{
			//Try again
			Sleep(100);
			continue;
		}

		server_connect_success = true;
	}

	return server_connect_success;
}

bool encrypt_send_module(proxy_client *client, unsigned char *module_data, unsigned int module_size)
{
	//Encrypt module data
	xor_encrypt_decrypt("\xDE\xAD", 2, (char*)module_data, module_size);

	constexpr int mtu = 8192;

	int split_max_count = module_size / mtu;

	bool send_packet_success = false;
	unsigned char send_packet_count = 0;

	for (int i = 0; i < split_max_count; ++i)
	{
		auto split_data = module_data + (i * mtu);
		auto split_packet = vac_module_split(module_size, split_data, mtu, i);

		send_packet_success = false;
		send_packet_count = 0;

		while (!send_packet_success && send_packet_count < 10)
		{
			++send_packet_count;

			if (!client->send_packet(split_packet.get_data(), split_packet.get_size()))
				continue;

			send_packet_success = true;
		}

		if (!send_packet_success)
			return false;
	}

	if (module_size % mtu != 0)
	{
		auto left = module_size % mtu;
		auto split_data = module_data + module_size - left;

		auto split_packet = vac_module_split(module_size, split_data, left, split_max_count);

		send_packet_success = false;
		send_packet_count = 0;

		while (!send_packet_success && send_packet_count < 10)
		{
			++send_packet_count;

			if (!client->send_packet(split_packet.get_data(), split_packet.get_size()))
				continue;

			send_packet_success = true;
		}

		if (!send_packet_success)
			return false;
	}

	//Decrypt module again
	xor_encrypt_decrypt("\xDE\xAD", 2, (char*)module_data, module_size);

	return send_packet_success;
}

std::wstring save_module(const std::vector<unsigned char> &Module)
{
	if (!CreateDirectoryW((cheat_path + L"\\modules").c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
		panic_crash(__LINE__);

	auto hash = HashPEHeader((unsigned char*)Module.data());
	auto module_name = cheat_path + L"\\modules\\" + std::wstring(hash.begin(), hash.end()) + std::to_wstring(GetTickCount()) + L".dll";

	std::ofstream module_file(module_name, std::ofstream::binary | std::ofstream::trunc);

	if (module_file)
	{
		module_file.write((char*)Module.data(), Module.size());
		module_file.close();

		return module_name;
	}
	else
	{
		return L"";
	}
}

class DisconnectException : public std::exception
{};

void get_response(int function_id, unsigned char* vac_parameters, int parameters_size, unsigned char* vac_result_out, int* vac_result_out_size)
{
	//VMProtectBegin("get_response");
	if (vac_result_out == nullptr || vac_result_out_size == nullptr)
		panic_crash(__LINE__);

	if (ModuleVec == nullptr || ModuleVec->empty())
		panic_crash(__LINE__);

	if (client != nullptr)
		delete client;

	client = new proxy_client();

	std::cout << "Connecting to server..." << std::endl;

	//Connect to server
	if (!connect_to_server(client))
		throw DisconnectException();

	std::cout << "OK! Connected to server!" << std::endl;

	bool success_try = false;
	unsigned char try_count = 0;
	bool module_rejected = false;

	while ((!success_try && try_count < 3) || module_rejected)
	{
		++try_count;

		std::cout << "try_count: " << (int)try_count << std::endl;

		boost::array<unsigned char, 0x2000> recv_buf;

		//Not already connected?
		if (!client->is_connected())
			throw DisconnectException();

		std::cout << "Sending module: {size: 0x" << ModuleVec->size() << "}" << std::endl;

		//Send module
		if (!encrypt_send_module(client, (unsigned char*)ModuleVec->data(), ModuleVec->size()))
		{
			std::cout << "Failed to send module: 0x" << std::hex << ModuleVec->size() << std::endl;

			//Try again
			Sleep(2000);
			continue;
		}

		std::cout << "OK! Module sent." << std::endl;

		//Hehehhe
		unsigned char ParserData[0x1400];
		memset(ParserData, 0x0, 0x1400);
		int ParserDataSize = 0x1000;

		auto hash = HashPEHeader(ModuleVec->data());
		std::cout << "HashPEHeader: " << hash << std::endl;

		bool isCrashing = ModuleVec->size() == 0x6c00 || ModuleVec->size() == 0x1c400 || hash == "0b7e0a275fdd50a461fbd1e265352e66" || hash == "52f5c866fed0db113bf08824ca67e1e5" || hash == "dd12a7451ae1f92cfcd73628165894d8" || hash == "e983e2fc61dae402b2fb404aca9e28c7" || hash == "ad37327cc2215d1e8a8e7bff9d2ce276" || hash == "3244980c147202f38924b4e7cdf10eed";

		std::cout << "Saving module..." << std::endl;
		auto module_path = save_module(*ModuleVec);
		std::wcout << L"OK! Module saved to " << module_path << std::endl;

		if (module_path.empty())
			panic_crash(__LINE__);

		if (!isCrashing)
		{
			std::cout << "Loading module..." << std::endl;
			auto Module = LoadLibraryW(module_path.c_str());
			std::cout << "OK! Loaded to 0x" << std::hex << Module << std::endl;

			if (Module == nullptr)
			{
				MessageBoxA(nullptr, std::to_string(GetLastError()).c_str(), "Module is nullptr", MB_TOPMOST);
				panic_crash(__LINE__);
			}

			auto runfunc = (runfunc_t)GetProcAddress(Module, "_runfunc@20");
			std::cout << "runfunc: 0x" << std::hex << runfunc << std::endl;

			if (runfunc == nullptr)
				panic_crash(__LINE__);

			//Hook them shit
			auto proc = GetVACProcChecksumProc(*ModuleVec, std::vector<unsigned char>{ vac_parameters, vac_parameters + parameters_size }, Module);

			if (proc == nullptr)
			{
				//Invalid module
				*(unsigned long*)(vac_result_out + 8) = -1;
				*(unsigned long*)(vac_result_out) = *(unsigned long*)(vac_parameters + 12);
				*(unsigned long*)(vac_result_out + 4) = 1;

				FreeLibrary(Module);
				//_wremove(module_path.c_str());
				g_mutex.unlock();

				std::cout << "Invalid module. proc == nullptr." << std::endl;
				MessageBoxW(nullptr, L"Invalid module", L"ok", MB_TOPMOST);
				return;
			}

			if (!proc->ProcAddress)
				panic_crash(__LINE__);

			procTrampoline = (ProcAnalyze_t)DetourFunction((unsigned char*)proc->ProcAddress, (unsigned char*)procHook);

			if (!procTrampoline)
				panic_crash(__LINE__);

			bool procCalled = false;

			//Create lambda
			procLambda = [&](unsigned char *VacOut, unsigned long VacOutSize)
			{
				procCalled = true;

				std::cout << "Now in procLambda!" << std::endl;
				std::cout << "Creating request..." << std::endl;

				//Send request
				auto request = vac_request(function_id, parameters_size, VacOutSize, vac_parameters, std::vector<unsigned char>{VacOut, VacOut + VacOutSize});

				std::cout << "OK! Request created." << std::endl;

				std::cout << "Sending request..." << std::endl;

				if (!client->send_packet(request.get_data(), request.get_size()))
				{
					std::cout << "Failed! Could not send request." << std::endl;
					throw DisconnectException();
				}

				std::cout << "OK! Request sent." << std::endl;
			};

			vac_module = (unsigned long)Module;

			std::cout << "Calling runfunc..." << std::endl;

			//procHook gets called
			runfunc(function_id, vac_parameters, parameters_size, ParserData, &ParserDataSize);

			std::cout << "OK! runfunc called!" << std::endl;

			if (!procCalled)
				panic_crash(__LINE__);

			FreeLibrary(Module);
		}
		else //Another send request in procHook
		{
			std::cout << "Creating request for server..." << std::endl;
			//Send request
			auto request = vac_request(function_id, parameters_size, *vac_result_out_size, vac_parameters, std::vector<unsigned char>{ParserData, ParserData + ParserDataSize});

			std::cout << "OK! Request created." << std::endl;
			std::cout << "Sending packet: {size: 0x" << request.get_size() << "}..." << std::endl;

			if (!client->send_packet(request.get_data(), request.get_size()))
			{
				std::cout << "Failed! Trying again..." << std::endl;
				//Try again
				Sleep(2000);
				continue;
			}

			std::cout << "OK! Request sent." << std::endl;
		}

		//Remove module again
		_wremove(module_path.c_str());

		std::cout << "Receiving response..." << std::endl;

		//Get response
		auto bytes_transferred = client->recv_packet(recv_buf.data(), recv_buf.size());

		if (bytes_transferred <= 0)
		{
			std::cout << "Failed. Trying again..." << std::endl;

			//Try again
			Sleep(2000);
			continue;
		}

		std::cout << "OK! Response received." << std::endl;

		std::string permission_str = (char*)recv_buf.data();
		if (permission_str.length() && permission_str == "NOT_GRANTED")
		{
			MessageBoxA(0, "You terminated omdis.exe OR your network connections seems to be unstable", "Error", MB_TOPMOST);
			exit(0);
		}

		auto header = (packet_header*)recv_buf.data();

		if (bytes_transferred < sizeof(packet_header))
		{
			std::cout << "Not enough bytes for packet_header" << std::endl;

			//Try again
			Sleep(2000);
			continue;
		}

		if (bytes_transferred - sizeof(packet_header) < header->body_size)
		{
			std::cout << "Not correct body size: " << bytes_transferred - sizeof(packet_header) << "bytes for body but " << header->body_size << " needed." << std::endl;

			//Try again
			Sleep(2000);
			continue;
		}

		if (header->magic != 0x1337)
		{
			std::cout << "Not correct magic signature: 0x" << std::hex << header->magic << std::dec << std::endl;

			//Try again
			Sleep(2000);
			continue;
		}

		//New module received?
		if (header->id == vac_new_module_id)
		{
			std::cout << "We sent an unknown module to the server." << std::endl;
			Sleep(INFINITE);
		}

		//Module rejected?
		if (header->id == vac_file_error_id)
		{
			std::wcout << "Module rejected. Sending again!" << std::endl;
			module_rejected = true;
			continue;
		}

		if (header->id != vac_response_id)
		{
			std::cout << "Expected a response opcode but received: " << header->id << std::endl;

			//Try again
			Sleep(2000);
			continue;
		}

		module_rejected = false;

		std::cout << "Parsing response..." << std::endl;
		auto response = vac_response(recv_buf.data() + sizeof(packet_header), header->body_size);
		std::cout << "OK! Response parsed." << std::endl;

		memcpy(vac_result_out, response.get_result(), response.get_result_size());
		*vac_result_out_size = response.get_result_size();

		success_try = true;
	}

	if (!success_try)
	{
		throw DisconnectException();
	}

	g_mutex.unlock();
}

int __stdcall runfunc_hook(int function_id, unsigned char* vac_parameters, int parameters_size, unsigned char* vac_result_out, int* vac_result_out_size)
{
	int tries = 0;
	bool exitLoop = false;

	if (!vac_parameters || !vac_result_out || !vac_result_out_size)
		panic_crash(__LINE__);

	while (!exitLoop)
	{
		if (tries > 10)
		{
			MessageBoxA(nullptr, "Connection can not be established", "OmdisCheats Network", MB_TOPMOST);
			ExitProcess(0);
		}

		try
		{
			get_response(function_id, vac_parameters, parameters_size, vac_result_out, vac_result_out_size);
			exitLoop = true;
		}
		catch (const DisconnectException&)
		{
			std::cout << "DisconnectException thrown." << std::endl;
			exitLoop = false;
			++tries;
		}
	}

	return 1;
}

bool __stdcall is_valid_module(VACModule* module_struct)
{
	auto module_data = module_struct->module_data_ptr;
	auto module_size = module_struct->module_size;

	if (module_size < 0x200
		|| *(WORD*)module_data != 23117
		|| *(DWORD*)(module_data + 60) < 0x40
		|| *(DWORD*)(module_data + 60) >= module_size - 248
		|| *(DWORD*)((*(DWORD*)(module_data + 60)) + module_data) != 17744)
		return false;

	if (*(DWORD*)(module_data + 64) != 5655638
		|| *(DWORD*)(module_data + 68) != 1
		|| module_size < *(DWORD*)(module_data + 72))
		return false;

	auto v6 = (*(DWORD*)(module_data + 60)) + module_data + 24;

	if (*(WORD*)v6 != 267 && *(WORD*)v6 != 523)
		return false;

	return true;
}

char __stdcall load_vac3_hook(VACModule* module_struct, char unk)
{
	g_mutex.lock();

	//Module was already loaded as the latest module. No need to load it again use old module
	if (module_struct->module_data_ptr && module_struct->module_size)
	{
		//Valid Module?
		if (!is_valid_module(module_struct))
		{
			std::cout << "Invalid module loaded: {size: 0x" << std::hex << module_struct->module_size << "}" << std::endl;

			module_struct->last_error_code = 11;
			module_struct->hModule = nullptr;
			module_struct->module_data_ptr = 0; //Memory Leak but I don't care
			module_struct->module_size = 0;
			module_struct->pModule = 0;
			module_struct->runfunc_func_ptr = nullptr;
			return 0;
		}

		//Save module
		if (ModuleVec)
			delete ModuleVec;

		std::cout << "Creating ModuleVec{size: " << module_struct->module_size << "}" << std::endl;

		ModuleVec = new std::vector<unsigned char>{ (unsigned char*)module_struct->module_data_ptr, (unsigned char*)module_struct->module_data_ptr + module_struct->module_size };
		module_struct->runfunc_func_ptr = runfunc_hook;
	}
	else if (module_struct->runfunc_func_ptr && module_struct->module_size)
	{
		module_struct->runfunc_func_ptr = runfunc_hook;
	}
	else
	{
		char buf[1024];
		sprintf_s(buf, 1024, "module_struct:\n hModule: 0x%X\n pModule: 0x%X\n last_error_code: %i\n module_data: 0x%X\n module_size: %i\n runfunc: 0x%X",
			module_struct->hModule, module_struct->pModule, module_struct->last_error_code, module_struct->module_data_ptr, module_struct->module_size, module_struct->runfunc_func_ptr);
		MessageBoxA(nullptr, buf, "debug", MB_TOPMOST);
		exit(0);
		return 0;
	}

	return 1;
}

void __cdecl main_thread(void*)
{
	g_service = new boost::asio::io_service();

	HMODULE steamservice_module = nullptr;

	while (steamservice_module == nullptr)
	{
		steamservice_module = GetModuleHandleA("steamservice.dll");
		Sleep(1000);
	}

	//55 8B EC 56 8B 75 08 57 8B F9 83 7E 0C 00 LoadVAC3 Pattern
	hook_addr = FindPattern((DWORD)steamservice_module, 0xc6000, (BYTE*)"\x55\x8B\xEC\x56\x8B\x75\x08\x57\x8B\xF9\x83\x7E\x0C\x00\x0F\x85\x00\x00\x00\x00", "xxxxxxxxxxxxxxxx????", 0);

	if (!hook_addr)
	{
		panic_crash(__LINE__);
	}

	//Create hook
	load_vac3_orig = (load_vac3_type)DetourFunction((BYTE*)hook_addr, (BYTE*)load_vac3_hook);

	//55 8B EC 8B 4D 0C 81 EC 94 VerifyModule Pattern
	hook_addr = FindPattern((DWORD)steamservice_module, 0xc6000, (BYTE*)"\x55\x8B\xEC\x8B\x4D\x0C\x81\xEC\x94", "xxxxxxxxx", 0);

	if (!hook_addr)
	{
		panic_crash(__LINE__);;
	}

}

void HideModule(HINSTANCE hModule)
{
	DWORD dwPEB_LDR_DATA = 0;
	_asm
	{
		pushad;
		pushfd;
		mov eax, fs:[30h]		   // PEB
			mov eax, [eax + 0Ch]		  // PEB->ProcessModuleInfo
			mov dwPEB_LDR_DATA, eax	 // Save ProcessModuleInfo

			InLoadOrderModuleList :
		mov esi, [eax + 0Ch]					  // ProcessModuleInfo->InLoadOrderModuleList[FORWARD]
			mov edx, [eax + 10h]					  //  ProcessModuleInfo->InLoadOrderModuleList[BACKWARD]

			LoopInLoadOrderModuleList :
			lodsd							   //  Load First Module
			mov esi, eax		    			//  ESI points to Next Module
			mov ecx, [eax + 18h]		    		//  LDR_MODULE->BaseAddress
			cmp ecx, hModule		    		//  Is it Our Module ?
			jne SkipA		    		    	//  If Not, Next Please (@f jumps to nearest Unamed Lable @@:)
			mov ebx, [eax]				  //  [FORWARD] Module
			mov ecx, [eax + 4]    		    	//  [BACKWARD] Module
			mov[ecx], ebx				  //  Previous Module's [FORWARD] Notation, Points to us, Replace it with, Module++
			mov[ebx + 4], ecx			    //  Next Modules, [BACKWARD] Notation, Points to us, Replace it with, Module--
			jmp InMemoryOrderModuleList		//  Hidden, so Move onto Next Set
			SkipA :
		cmp edx, esi					    //  Reached End of Modules ?
			jne LoopInLoadOrderModuleList		//  If Not, Re Loop

			InMemoryOrderModuleList :
		mov eax, dwPEB_LDR_DATA		  //  PEB->ProcessModuleInfo
			mov esi, [eax + 14h]			   //  ProcessModuleInfo->InMemoryOrderModuleList[START]
			mov edx, [eax + 18h]			   //  ProcessModuleInfo->InMemoryOrderModuleList[FINISH]

			LoopInMemoryOrderModuleList :
			lodsd
			mov esi, eax
			mov ecx, [eax + 10h]
			cmp ecx, hModule
			jne SkipB
			mov ebx, [eax]
			mov ecx, [eax + 4]
			mov[ecx], ebx
			mov[ebx + 4], ecx
			jmp InInitializationOrderModuleList
			SkipB :
		cmp edx, esi
			jne LoopInMemoryOrderModuleList

			InInitializationOrderModuleList :
		mov eax, dwPEB_LDR_DATA				    //  PEB->ProcessModuleInfo
			mov esi, [eax + 1Ch]						 //  ProcessModuleInfo->InInitializationOrderModuleList[START]
			mov edx, [eax + 20h]						 //  ProcessModuleInfo->InInitializationOrderModuleList[FINISH]

			LoopInInitializationOrderModuleList :
			lodsd
			mov esi, eax
			mov ecx, [eax + 08h]
			cmp ecx, hModule
			jne SkipC
			mov ebx, [eax]
			mov ecx, [eax + 4]
			mov[ecx], ebx
			mov[ebx + 4], ecx
			jmp Finished
			SkipC :
		cmp edx, esi
			jne LoopInInitializationOrderModuleList

			Finished :
		popfd;
		popad;
	}
}

wchar_t *GetModuleDir(HINSTANCE instance)
{
	wchar_t buffer[MAX_PATH];
	GetModuleFileNameW(instance, buffer, MAX_PATH);
	PathRemoveFileSpecW(buffer);
	return buffer;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		//cheat_path = (wchar_t*)lpvReserved;
		cheat_path = GetModuleDir(hinstDLL);
		std::wcout << "cheat_path: " << cheat_path << std::endl;

		_wmkdir((cheat_path + L"/logs").c_str());

		log_file = new std::ofstream(cheat_path + L"/logs/detailed_logs1.log");
		wlog_file = new std::wofstream(cheat_path + L"/logs/detailed_logs2.log");

		std::cout.rdbuf(log_file->rdbuf());
		std::wcout.rdbuf(wlog_file->rdbuf());

		DisableThreadLibraryCalls((HMODULE)hinstDLL);
		DetourFunction((PBYTE)atexit, (PBYTE)atexit_hook);
		HideModule(hinstDLL);

		_beginthread(main_thread, 0, nullptr);
	}

	return true;
}