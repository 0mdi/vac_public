#include "ModuleParser.hpp"

#include <algorithm>

bool Module8a00h::ParseFunction4(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	if (*VacOutSize != 264)
		throw ModuleParser::ParseException();
	
	//Change all
	memcpy(VacOut, ParserData, *VacOutSize);

	return true;
}

bool Module8a00h::ParseOutput(int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	switch (FunctionId)
	{
	case 4:
		Corrected = ParseFunction4(VacInput, VacInputSize, VacOut, VacOutSize, ParserData);
		break;

	default:
		throw std::exception("ParseFunction not implemented.");
	}

	return Corrected;
}