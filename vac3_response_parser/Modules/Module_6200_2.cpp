#include "ModuleParser.hpp"
#include "../ModuleUtils.hpp"

#include <iostream>

bool Module6200_2::Preprocess(unsigned long ModuleBase)
{
	return Module10c00h::Preprocess(ModuleBase);
}

bool Module6200_2::ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	if (FunctionId != 4)
		throw std::exception("FunctionID not implemented");

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	std::cout << "index: " << index << std::endl;

	switch (index)
	{
	case 0:
		Corrected = Module10c00h::ParseFunction4_4(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(index)).c_str());
	}

	return Corrected;
}
