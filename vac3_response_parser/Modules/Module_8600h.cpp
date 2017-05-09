#include "ModuleParser.hpp"
#include "../ModuleUtils.hpp"

#include <sstream>
#include <iostream>
#include <Windows.h>

/**
  * Parse Functions from 1 to 4, structure ripped from IDA
*/

template<class Elem, class Traits>
inline void hex_dump(const void* aData, std::size_t aLength, std::basic_ostream<Elem, Traits>& aStream, std::size_t aWidth = 16)
{
	const char* const start = static_cast<const char*>(aData);
	const char* const end = start + aLength;
	const char* line = start;
	while (line != end)
	{
		aStream.width(4);
		aStream.fill('0');
		aStream << std::hex << line - start << " : ";
		std::size_t lineLength = min(aWidth, static_cast<std::size_t>(end - line));
		for (std::size_t pass = 1; pass <= 2; ++pass)
		{
			for (const char* next = line; next != end && next != line + aWidth; ++next)
			{
				char ch = *next;
				switch (pass)
				{
				case 1:
					aStream << (ch < 32 ? '.' : ch);
					break;
				case 2:
					if (next != line)
						aStream << " ";
					aStream.width(2);
					aStream.fill('0');
					aStream << std::hex << std::uppercase << static_cast<int>(static_cast<unsigned char>(ch));
					break;
				}
			}
			if (pass == 1 && lineLength != aWidth)
				aStream << std::string(aWidth - lineLength, ' ');
			aStream << " ";
		}
		aStream << std::endl;
		line = line + lineLength;
	}
}

bool Module8600h::ParseFunction4(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	if (*VacOutSize == 16)
	{
#pragma pack(push, 1)
		struct VACOutput
		{
			unsigned long unk1;
			unsigned long unk2;
			unsigned long unk3;
			unsigned long unk4;
		};
#pragma pack(pop)


		auto Output = (VACOutput*)VacOut;

		if (Output->unk1 != 0
			|| Output->unk1 != *(unsigned long*)VacInput + 12)
				throw ModuleParser::ParseException();

		if (Output->unk2 != 0
			|| Output->unk2 != 1
			|| Output->unk2 != 2
			|| Output->unk2 != 3)
			throw ModuleParser::ParseException();

		if (Output->unk3 != 0
			|| Output->unk3 != -1)
			throw ModuleParser::ParseException();
	}
	else
	{

#pragma pack(push, 1)
		struct VACOutput
		{
			unsigned long VacInput12Value;
			unsigned long ProtReturn;
			unsigned long Unk3;
			unsigned long Unk4;
			unsigned long Checksum;
			unsigned long Unk5;
			unsigned long TimeOfDayResult;
			unsigned long CodeIntegrityInformationResult;
			unsigned long Checksum02;
			unsigned long Checksum03;
			unsigned long Checksum04;
			unsigned long Checksum05;
			unsigned long Checksum06;
			unsigned long Checksum07;
			unsigned long CurrentTime1;
			unsigned long CurrentTime2;
			unsigned long BootTime1;
			unsigned long BootTime2;
			unsigned long Version;
			unsigned long CodeIntegrityOptions;
			unsigned long OemId;
			unsigned long ProcessorType;
			unsigned long DeviceInformationResult;
			unsigned long KernelDebuggerInfoResult;
			unsigned long BootEnvInfoResult;
			unsigned long RangeStartInformationResult;
			unsigned long NumberOfDisks;
			bool KernelDebuggerEnabled;
			bool KernelDebuggerNotPresent;
			unsigned char padding01[2];
			unsigned long BootIdentifier1;
			unsigned long BootIdentifier2;
			unsigned long BootIdentifier3;
			unsigned long BootIdentifier4;
			unsigned long SystemRangeStart;
			unsigned long SystemRangeStartPadding;
			unsigned long CurrentProcessId;
			unsigned long CurrentThreadId;
			unsigned long LastErrorCode;
			char ImageFilename[36];
			unsigned long LastErrorCode2;
			unsigned long Unk6;
		};
#pragma pack(pop)

		//Get Xor Key and decrypt 444 * 4 bytes
		unsigned long xor_key = *(unsigned long*)(VacOut + 4) ^ 0x00000000;
		unsigned long xor_key_2 = *(unsigned long*)(((unsigned char*)ParserData) + 4) ^ 0x00000000;

		int CryptCounter = 444;

		do
		{
			*(unsigned long*)(VacOut + 4 * CryptCounter) ^= xor_key;
			*(unsigned long*)(((unsigned char*)ParserData) + 4 * CryptCounter) ^= xor_key_2;
			--CryptCounter;
		} while (CryptCounter);


		//std::ostringstream OutBuffer;
		//hex_dump(VacOut, *VacOutSize, OutBuffer);

		//MessageBoxA(nullptr, OutBuffer.str().c_str(), "", MB_TOPMOST);

		//OutBuffer.str("");
		//OutBuffer.clear();
		//hex_dump(ParserData, *VacOutSize, OutBuffer);

		//MessageBoxA(nullptr, OutBuffer.str().c_str(), "", MB_TOPMOST);

		auto Output = (VACOutput*)VacOut;
		auto FixData = (VACOutput*)ParserData;

		//Hide our cheat stuff :>
		Output->TimeOfDayResult = 0;
		Output->CodeIntegrityInformationResult = 0;
		Output->DeviceInformationResult = 0;
		Output->KernelDebuggerInfoResult = 0;
		Output->BootEnvInfoResult = 0;
		Output->RangeStartInformationResult = 0;

		Output->CurrentTime1 = FixData->CurrentTime1;
		Output->CurrentTime2 = FixData->CurrentTime2;
		Output->BootTime1 = FixData->BootTime1;
		Output->BootTime2 = FixData->BootTime2;
		Output->Version = FixData->Version;

		//TODO: Lookup CodeIntegrityOptions but leave it for now

		Output->OemId = FixData->OemId;
		Output->ProcessorType = FixData->ProcessorType;
		Output->NumberOfDisks = FixData->NumberOfDisks;

		Output->KernelDebuggerEnabled = false;
		Output->KernelDebuggerNotPresent = true;

		Output->BootIdentifier1 = FixData->BootIdentifier1;
		Output->BootIdentifier2 = FixData->BootIdentifier2;
		Output->BootIdentifier3 = FixData->BootIdentifier3;
		Output->BootIdentifier4 = FixData->BootIdentifier4;

		Output->SystemRangeStart = FixData->SystemRangeStart;
		Output->SystemRangeStartPadding = FixData->SystemRangeStartPadding;

		Output->CurrentProcessId = FixData->CurrentProcessId;
		Output->CurrentThreadId = FixData->CurrentThreadId;

		//TODO: Lookup if that is safe
		Output->LastErrorCode = 0;
		Output->LastErrorCode2 = 0;

		std::string strFilename = FixData->ImageFilename;

		if (strFilename.find("Steam.exe") == std::string::npos)
			throw std::exception("Packet structure changed!");

		strcpy(Output->ImageFilename, FixData->ImageFilename);
		memcpy(VacOut + 0xC0, ((unsigned char*)ParserData) + 0xC0, 0x10);

		//MessageBoxA(nullptr, Output->ImageFilename, "ImageFileName", MB_TOPMOST);

		//Encrypt again
		CryptCounter = 444;

		do
		{
			*(unsigned long*)(VacOut + 4 * CryptCounter) ^= xor_key;
			*(unsigned long*)(((unsigned char*)ParserData) + 4 * CryptCounter) ^= xor_key_2;
			--CryptCounter;
		} while (CryptCounter);
	}
	
	return true;
}

bool Module8600h::ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	if (FunctionId != 4)
		throw std::exception("FunctionID not implemented");

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	std::cout << "index: " << index << std::endl;

	switch (index)
	{
	case 1:
		Corrected = ParseFunction4(VacInput, VacInputSize, VacOut, VacOutSize, ParserData);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(index)).c_str());
	}

	return Corrected;
}