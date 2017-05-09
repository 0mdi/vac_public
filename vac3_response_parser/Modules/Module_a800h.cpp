#include "ModuleParser.hpp"
#include "../ModuleUtils.hpp"

bool Modulea800h::ParseFunction4_1(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
//#pragma pack(push, 1)
//	struct VACOutput_4_1
//	{
//		unsigned long VacInput12Value;
//		unsigned long ProcReturn;
//		unsigned long Unk1;
//		unsigned long Checksum1;
//		unsigned long LastError;
//	};
//#pragma pack(pop)
//
//	auto Output = (VACOutput_4_1*)VacOut;
//
//	Output->Checksum1 = 1799191836;
//	Output->LastError = 5; //Error Access Denied
//
	return true;
}

bool Modulea800h::ParseFunction4_2(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	return true;
}

bool Modulea800h::ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	switch (GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase))
	{
	//case 0x5B0B236:
	case 0:
		Corrected = true;
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//case 0x23FD411:
	case 1:
		Corrected = true;
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//case 0x46A224B:
	case 2:
		Corrected = true;
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	default:
		throw std::exception("ParseFunction not implemented.");
	}

	return Corrected;
}