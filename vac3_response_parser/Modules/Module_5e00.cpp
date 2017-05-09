#include "ModuleParser.hpp"
#include "../ModuleUtils.hpp"

#include <iostream>

bool Module5e00::ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize)
{
	*VacOutSize = 4096;

	memset(VacOut, 0x00, 4096);
	*(unsigned long*)(VacOut + 16) = -1226040339;
	*(unsigned long*)(VacOut + 20) = 78;

	return true;
}

bool Module5e00::ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, unsigned long ModuleBase)
{
	bool Corrected = false;

	if (FunctionId != 4)
		throw std::exception("FunctionID not implemented");

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	std::cout << "index: " << index << std::endl;

	switch (index)
	{
	case 0:
		Corrected = ParseFunction1(VacOut, VacOutSize);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(index)).c_str());
	}

	return Corrected;
}
