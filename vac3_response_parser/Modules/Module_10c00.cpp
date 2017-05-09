#include "ModuleParser.hpp"
#include "../Preprocessor/Preprocessor.hpp"
#include "../VACStringArray.hpp"
#include "../ModuleUtils.hpp"

#include "Blacklist.hpp"

#include <algorithm>

#include <iostream>

#include <Windows.h>
#include "../detours.h"

Module10c00h::HashString_t Module10c00h::HashStringOrig = nullptr;

int __fastcall Module10c00h::HashStringHook(char *String, int Length)
{
	try
	{
		CheckPacketDangerous((unsigned char*)String, (unsigned long*)&Length);
	}
	catch (const std::exception&)
	{
		std::cout << "Preprocessor: " << String << " blacklisted!" << std::endl;
		return 0xDEADBEEF;
	}

	if (HashStringOrig == nullptr)
		throw std::exception("HashStringOrig is nullptr");

	return HashStringOrig(String, Length);
}

bool Module10c00h::Preprocess(unsigned long ModuleBase)
{
	//Hook str_checksum in this module to blacklist our cheat stuff and remove it later when parsing
	//To mark blacklisted stuff use 0xDEADBEEF as hash 

	auto addr = (unsigned char*)FindPattern(ModuleBase, 0x9000, (unsigned char*)"\xB8\x92\x18\xD7\x45\x85\xD2", "xxxxxxx", 0);

	if (addr == nullptr)
		throw std::exception("str_checksum Pattern outdated");

	//Hook it now
	HashStringOrig = (HashString_t)DetourFunction((unsigned char*)addr, (unsigned char*)HashStringHook);
}

bool Module10c00h::ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	if (FunctionId != 4)
		throw std::exception("FunctionID not implemented");

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	std::cout << "index: " << index << std::endl;

	switch (index)
	{
	case 0:
		Corrected = false;
		break;

	case 3:
		Corrected = ParseFunction4_3(VacOut, VacOutSize, VacInput, VacInputSize, ParserData);
		break;

	case 4:
		Corrected = false;
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//Dumps modules of a process
	case 2:
		Corrected = ParseFunction4_4(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData);
		break;

	case 1:
		Corrected = ParseFunction4_2(VacOut, VacOutSize, ParserData);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(index)).c_str());
	}
}

bool Module10c00h::ParseFunction4_2(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	memcpy(VacOut, ParserData, *VacOutSize);

	//Remove every suspicious string: ocsXXXX.tmp
	//Next string eventually path (check for \Local\Temp)
	unsigned long result = 0;

	do
	{
		result = FindPattern((unsigned long)VacOut, *VacOutSize, (unsigned char*)"\x6F\x63\x73\x00\x00\x00\x00", "xxx???", 0);

		if (result)
		{
			auto ocs_len = strlen((char*)result) + 1;
			auto next_str = result + ocs_len;
			std::string str = (char*)next_str;

			//Zero out ocsXXXX.tmp
			memset((void*)result, 0x00, ocs_len);

			//Adjust string list
			std::copy((unsigned char*)result + ocs_len, VacOut + *VacOutSize, (unsigned char*)result);
			memset(VacOut + *VacOutSize - ocs_len, 0x00, ocs_len);

			if (str.find("cheat_files") != std::string::npos)
			{
				while (*(char*)next_str)
					--next_str;

				std::cout << str << std::endl;
				memset((void*)next_str, 0x00, str.length());

				//Adjust string list
				std::copy((unsigned char*)next_str + str.length(), VacOut + *VacOutSize, (unsigned char*)next_str);
				memset(VacOut + *VacOutSize - str.length(), 0x00, str.length());

			}
		}

	} while (result);

	//Loop through BlacklistProcessName
	for (auto blacklisted : BlacklistProcessName)
	{
		std::string mask;

		for (int i = 0; i < blacklisted.length(); ++i)
			mask += 'x';

		unsigned long it = 0;

		do
		{
			it = FindPattern((unsigned long)VacOut, *VacOutSize, (unsigned char*)blacklisted.c_str(), (char*)mask.c_str(), 0);

			if (it)
			{
				auto len = strlen((char*)it) + 1;

				//Zero out ocsXXXX.tmp
				memset((void*)it, 0x00, len);

				//Adjust string list
				std::copy((unsigned char*)it + len, VacOut + *VacOutSize, (unsigned char*)it);
				memset(VacOut + *VacOutSize - len, 0x00, len);
			}
		} while (it);
	}

	return true;
}

bool Module10c00h::ParseFunction4_3(unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData)
{
	//Replace VacOut with ParserData
	memcpy(VacOut, ParserData, *VacOutSize);

	//If packet is dangerous
	try
	{
		CheckPacketDangerous(VacOut, VacOutSize);
	}
	catch (...)
	{
		memset(VacOut, 0x00, *VacOutSize);
		*(unsigned long*)(VacOut + 16) = 78;
	}
	
	return true;
}

int str_hash(std::string str)
{
	int hash = 1171724434;

	if (str.empty())
		return -1;

	for (int i = 0; i < str.length(); ++i)
		hash = (str.at(i) | 0x20) + 33 * hash;

	return hash;
}

bool Module10c00h::ParseFunction4_4_new(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
#pragma pack(push, 1)
	struct VACProcessBlock4_3
	{
		unsigned long ImageNameHash;
		unsigned long ProcessNameHash;
		unsigned long ProcessId;
		unsigned long Dunno;
		unsigned long HighLvlBitShiftingStuff;
		unsigned long field_14;
		unsigned long TimeRelatedStuff;
	};

	struct VACOutput_4_3
	{
		unsigned long VacInput12Value;
		unsigned long ProcReturn;
		unsigned long Padding[4];
		unsigned long ProcessCount2;
		unsigned long Padding2[2];
		unsigned long ProcessCountShit;
	};
#pragma pack(pop)

	//Replace VacOut with ParserData
#ifndef _DEBUG
	memcpy(VacOut, ParserData, *VacOutSize);
#endif

	//Fix it remove every suspicious thing
	auto Output = (VACOutput_4_3*)VacOut;
	auto ProcessBlock = (VACProcessBlock4_3*)(VacOut + 64);
	

	//Loop through every process
	std::vector<VACProcessBlock4_3*> BlacklistedBlocks;

	for (int i = 0, j = 0; i < Output->ProcessCount2 - 1; ++i, ++ProcessBlock)
	{
		bool Blacklisted = false;

		//Look for blacklsited module by Preprocessor
		if (ProcessBlock->ProcessNameHash == 0xDEADBEEF ||
			ProcessBlock->ImageNameHash == 0xDEADBEEF)
		{
			std::cout << "0xDEADBEEF found!\n";
			Blacklisted = true;
		}

		if (!Blacklisted)
		{
			//To be sure check it again
			for (auto Black : BlacklistProcessName)
			{
				if (str_hash(Black) == ProcessBlock->ProcessNameHash)
				{
					std::cout << "Black one found! -> " << Black << std::endl;
					Blacklisted = true;
					break;
				}
			}
		}

		if (Blacklisted)
			BlacklistedBlocks.push_back(ProcessBlock);
	}


	for (auto BlockedBlock : BlacklistedBlocks)
	{
		memset(BlockedBlock, 0x00, sizeof(VACProcessBlock4_3));

		auto StartBlock = (VACProcessBlock4_3*)(VacOut + 64);

		//Is last element?
		if (BlockedBlock == StartBlock + Output->ProcessCount2 - 1)
		{
			--Output->ProcessCount2;

			memset(BlockedBlock, 0x00, sizeof(VACProcessBlock4_3));
		}
		else
		{
			std::copy(BlockedBlock + 1, StartBlock + Output->ProcessCount2, BlockedBlock);
			memset(StartBlock + Output->ProcessCount2 - 1, 0x00, sizeof(VACProcessBlock4_3));
			--Output->ProcessCount2;

			//Adjust blocked blocks according to the new order
			for (auto &BlockToFix : BlacklistedBlocks)
			{
				if (BlockToFix != BlockedBlock)
					--BlockToFix;
			}
		}
	}


	return true;
}

bool Module10c00h::ParseFunction4_4(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData)
{
#pragma pack(push, 1)
	struct VACProcessBlock4_3
	{
		unsigned long ImageNameHash;
		unsigned long ProcessNameHash;
		unsigned long ProcessId;
		unsigned long LastErrorCode;
		unsigned long CreationTimeLowDateTime;
		unsigned long CreationTimeHighDateTime;
		unsigned long Unknown;
	};

	struct VACOutput_4_3
	{
		unsigned long VacInput12Value;
		unsigned long ProcReturn;
		unsigned long Padding[4];
		unsigned long ProcessCount2;
		unsigned long Padding2[2];
		unsigned long ProcessCount;
	};
#pragma pack(pop)

	//Replace VacOut with ParserData
#ifndef _DEBUG
	memcpy(VacOut, ParserData, *VacOutSize);
#endif

	//Fix it remove every suspicious thing
	auto Output = (VACOutput_4_3*)VacOut;
	auto ProcessBlock = (VACProcessBlock4_3*)(VacOut + 64);
	auto Offset76 = (VACProcessBlock4_3*)(VacOut + 76);

	//Fetch all strings
	VACStringArray StringList((char*)(ProcessBlock + Output->ProcessCount));

	//Loop through every process
	std::vector<VACProcessBlock4_3*> BlacklistedBlocks;

	for (int i = 0, j = 0; i < Output->ProcessCount - 1; ++i, ++ProcessBlock, ++Offset76)
	{
		bool HasName = false;
		bool HasDevicePath = false;
		bool Blacklisted = false;

		if (*((unsigned long*)Offset76 - 2))
			HasName = Offset76->ImageNameHash & 1;

		if (*((unsigned long*)Offset76 - 3))
			HasDevicePath = Offset76->ProcessNameHash & 2;

		//0xDEADBEEF
		if (ProcessBlock->ProcessNameHash == 0xDEADBEEF ||
			ProcessBlock->ImageNameHash == 0xDEADBEEF)
		{
			std::cout << "0xDEADBEEF found!\n";
			Blacklisted = true;
		}

		//Checksums
		//for (auto BlackChecksum : BlacklistChecksums)
		//{
		//	if (ProcessBlock->Checksum1 == BlackChecksum || ProcessBlock->Checksum2 == BlackChecksum)
		//	{
		//		Blacklisted = true;
		//		break;
		//	}
		//}

		//Strings
		if (HasName && j < StringList.GetSize())
		{
			if (Blacklisted)
			{
				std::cout << StringList.Get(j) << " removed\n";
				StringList.Remove(j);
			}
			else
			{
				for (auto Black : BlacklistProcessName)
				{
					if (j >= StringList.GetSize())
						break;

					if (std::string(StringList.Get(j)).find(Black) != std::string::npos)
					{
						std::cout << StringList.Get(j) << " removed\n";
						Blacklisted = true;
						StringList.Remove(j);
					}
				}

				if (!Blacklisted)
					++j;
			}
		}
		
		if (HasDevicePath && j < StringList.GetSize())
		{
			if (Blacklisted)
			{
				std::cout << StringList.Get(j) << " removed\n";
				StringList.Remove(j);
			}
			else
			{
				for (auto Black : BlacklistProcessName)
				{
					if (j >= StringList.GetSize())
						break;

					if (std::string(StringList.Get(j)).find(Black) != std::string::npos)
					{
						std::cout << StringList.Get(j) << " removed\n";
						Blacklisted = true;
						StringList.Remove(j);
					}
				}

				if (!Blacklisted)
					++j;
			}
		}

		if (Blacklisted)
			BlacklistedBlocks.push_back(ProcessBlock);
	}


	for (auto BlockedBlock : BlacklistedBlocks)
	{
		BlockedBlock->ImageNameHash = 0x0;
		BlockedBlock->ProcessNameHash = 0x0;
		BlockedBlock->CreationTimeHighDateTime = 0x0;
		BlockedBlock->CreationTimeLowDateTime = 0x0;
		BlockedBlock->LastErrorCode = 0x0;
		BlockedBlock->ProcessId = 0x0;
		BlockedBlock->Unknown = 0x0;

		auto StartBlock = (VACProcessBlock4_3*)(VacOut + 64);

		//Is last element?
		if (BlockedBlock == StartBlock + Output->ProcessCount - 1)
		{
			//std::cout << "First Block" << std::endl;

			--Output->ProcessCount;
			--Output->ProcessCount2;

			memset(BlockedBlock, 0x00, sizeof(VACProcessBlock4_3));
		}
		else
		{
			std::copy(BlockedBlock + 1, StartBlock + Output->ProcessCount, BlockedBlock);
			memset(StartBlock + Output->ProcessCount - 1, 0x00, sizeof(VACProcessBlock4_3));
			--Output->ProcessCount;
			--Output->ProcessCount2;

			//Adjust blocked blocks according to the new order
			for (auto &BlockToFix : BlacklistedBlocks)
			{
				if (BlockToFix != BlockedBlock)
					--BlockToFix;
			}
		}
	}


	return true;
}