#include "ModuleParser.hpp"

#include "../ModuleUtils.hpp"

bool Module8200h::ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);


	switch (index)
	{
	//Sends Page Protect & Alloc Protect of current process to server
	case 0:
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//Dumps info about a specific process
	case 1:
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(index)).c_str());
	}
}