#include "ModuleParser.hpp"
#include "../ModuleUtils.hpp"

#include <iostream>

bool ModuleHandleInvestigator::ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	memset(VacOut, 0, *VacOutSize);
	*(uint32_t*)(VacOut + 16) = -1226040339;
	return true;
}

bool ModuleHandleInvestigator::ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	std::cout << "index: " << index << std::endl;

	switch (index)
	{
	case 0:
		Corrected = ParseFunction1(VacOut, VacOutSize, ParserData);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(index)).c_str());
	}

	return Corrected;
}
