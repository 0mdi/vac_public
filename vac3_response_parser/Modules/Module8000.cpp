#include "ModuleParser.hpp"
#include "../ModuleUtils.hpp"

#include <iostream>

bool Module8000::ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	return Module9a00h::ParseFunction2(VacOut, VacOutSize, ParserData);
}

bool Module8000::ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	if (FunctionId != 4)
		throw std::exception("FunctionID not implemented");

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	std::cout << "index: " << index << std::endl;

	switch (index)
	{
	case 1:
		Corrected = ParseFunction1(VacOut, VacOutSize, ParserData);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(index)).c_str());
	}

	return Corrected;
}
