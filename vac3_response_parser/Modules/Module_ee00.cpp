#include "ModuleParser.hpp"
#include "../VACStringArray.hpp"

#include "Blacklist.hpp"
#include "../ModuleUtils.hpp"

#include <algorithm>

#include <iostream>



bool Moduleee00h::ParseFunction4_3(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData)
{
#pragma pack(push, 1)
	struct VACProcessBlock4_3
	{
		unsigned long Checksum1;
		unsigned long Checksum2;
		unsigned long ProcessId;
		unsigned long LastErrorCode;
		unsigned long CreationTimeLowDateTime;
		unsigned long CreationTimeHighDateTime;
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

	std::cout << "StringList Offset: 0x" << std::hex << ((unsigned long)(ProcessBlock + Output->ProcessCount)) - (unsigned long)VacOut << std::endl;

	//Loop through every process
	std::vector<VACProcessBlock4_3*> BlacklistedBlocks;

	for (int i = 0, j = 0; i < Output->ProcessCount - 1; ++i, ++ProcessBlock, ++Offset76)
	{
		bool HasName = false;
		bool HasDevicePath = false;
		bool Blacklisted = false;

		if (*((unsigned long*)Offset76 - 2))
			HasName = Offset76->Checksum1 & 1;

		if (*((unsigned long*)Offset76 - 3))
			HasDevicePath = Offset76->Checksum1 & 2;

		//Checksums
		for (auto BlackChecksum : BlacklistChecksums)
		{
			if (ProcessBlock->Checksum1 == BlackChecksum || ProcessBlock->Checksum2 == BlackChecksum)
			{
				Blacklisted = true;
				break;
			}
		}

		//Strings
		if (HasName)
		{
			if (Blacklisted)
			{
				StringList.Remove(j);
			}
			else
			{
				for (auto Black : BlacklistProcessName)
				{
					if (std::string(StringList.Get(j)).find(Black) != std::string::npos)
					{
						Blacklisted = true;
						StringList.Remove(j);
					}
				}

				if (!Blacklisted)
					++j;
			}
		}

		if (HasDevicePath)
		{
			if (Blacklisted)
			{
				StringList.Remove(j);
			}
			else
			{
				for (auto Black : BlacklistProcessName)
				{
					if (std::string(StringList.Get(j)).find(Black) != std::string::npos)
					{
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
		BlockedBlock->Checksum1 = 0x0;
		BlockedBlock->Checksum2 = 0x0;
		BlockedBlock->CreationTimeHighDateTime = 0x0;
		BlockedBlock->CreationTimeLowDateTime = 0x0;
		BlockedBlock->LastErrorCode = 0x0;
		BlockedBlock->ProcessId = 0x0;

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

bool Moduleee00h::ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	if(FunctionId != 4)
		throw std::exception("FunctionID not implemented");
	
	switch (GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase))
	{
	//case 0x9228675:
	case 2:
		Corrected = ParseFunction4_3(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData);
		break;

	default:
		throw std::exception("Undefined Proc requested");
	}

	return Corrected;
}