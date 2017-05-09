#include "ModuleParser.hpp"

bool Module1c400h::ParseOutput(unsigned char *VacOut, unsigned long *VacOutSize)
{
	return ParseFunction1(VacOut, VacOutSize);
}

bool Module1c400h::ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize)
{
	*VacOutSize = 0x1000;
	memset(VacOut, 0x00, 0x1000);

	*(unsigned long*)(VacOut + 32) = 963210198;
	*(unsigned long*)(VacOut + 36) = 78;

	return true;
}