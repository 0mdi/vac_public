#include "ModuleParser.hpp"

#include "../ModuleUtils.hpp"

bool ModuleUserEnv::ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;
	int Index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	switch (Index)
	{
	case 0:
		Corrected = ParseFunction1(VacOut, VacOutSize, VacInput, VacInputSize, ParserData);
		break;

	case 2:
		Corrected = ParseFunction3(VacOut, VacOutSize, VacInput, VacInputSize, ParserData);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(Index)).c_str());
	}
}

bool ModuleUserEnv::ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacIn, unsigned long VacInputSize, void *ParserData)
{
	//ParserData is relevant
	memcpy(VacOut, ParserData, *VacOutSize);

	return true;
}

bool ModuleUserEnv::ParseFunction3(unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacIn, unsigned long VacInputSize, void *ParserData)
{
	//ParserData is relevant
	memcpy(VacOut, ParserData, *VacOutSize);

	auto Filename = (char *)(VacIn + 56);

	if (Filename)
	{
		unsigned long Length = strlen(Filename);
		CheckPacketDangerous((unsigned char*)Filename, &Length);
	}

	return true;
}