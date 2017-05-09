#include "ModuleParser.hpp"

#include "../ModuleUtils.hpp"

bool ModuleFileSystemCtrl::ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;
	/*int Index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	switch (Index)
	{
	case 0:*/
		Corrected = ParseFunction1(VacOut, VacOutSize, ParserData);
		/*break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(Index)).c_str());
	}*/
		return Corrected;
}

bool ModuleFileSystemCtrl::ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	//ParserData is relevant
	//memcpy(VacOut, ParserData, *VacOutSize);

	unsigned char *FixData = (unsigned char*)ParserData;
	
	//Change VolumeSerial
	memcpy(VacOut + 14, FixData + 14, 4);

	//NtFsControlFile - 590068
	memcpy(VacOut + 12 * 4, FixData + 12 * 4, 4);
	memcpy(VacOut + 13 * 4, FixData + 13 * 4, 4);

	return true;
}