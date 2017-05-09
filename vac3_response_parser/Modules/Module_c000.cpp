#include "ModuleParser.hpp"

#include "../ModuleUtils.hpp"

bool Modulec000::ParseOutput(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{

	//ParserData dangerous - like dumping one of our modules
	try
	{
		CheckPacketDangerous((unsigned char*)ParserData, VacOutSize);
	}
	catch (const std::exception&)
	{
		return false;
	}

	memcpy(VacOut, ParserData, *VacOutSize);

	return true;
}