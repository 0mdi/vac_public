#include "ModuleParser.hpp"


bool Module6200h::ParseOutput(int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize)
{
	bool Corrected = false;

	switch (FunctionId)
	{
	case 4:
		Corrected = ParseFunction4(VacOut, VacOutSize);
		break;

	default:
		throw std::exception("ParseFunction not implemented.");
	}

	return Corrected;
}

bool Module6200h::ParseFunction4(unsigned char *VacOut, unsigned long *VacOutSize)
{
	*VacOutSize = 0x20;
	*(unsigned long*)(VacOut + 16) = 887514048;

	unsigned __int64 v3;
	unsigned long BeingDebugged;
	unsigned long v5;

	if (0 | 0)
	{
		v3 = 0 * (unsigned __int64)0xFA00000 >> 24;

		v3 = (v3 & 0xFFFFFFFF00000000) | ((0xFA00000 * (0 << 8) + v3) & 0x00000000FFFFFFFF);
		//v3 = 0xFA00000 * (0 << 8) + v3;
	}
	else
	{
		v3 = 0xFA00000 * (unsigned __int64)0;
		v3 = (v3 & 0xFFFFFFFF00000000) | ((0xFA00000 * (unsigned __int64)0 >> 24) & 0x00000000FFFFFFFF);
		//v3 = 0xFA00000 * (unsigned __int64)0 >> 24;
	}
	*(unsigned long*)(VacOut + 20) ^= (((unsigned int)v3 >> 7) + 255) & 0xFFFFFF00;
	BeingDebugged = 0;
	*(unsigned long*)(VacOut + 24) = BeingDebugged;
	*(unsigned long*)(VacOut + 20) ^= 99999999;

	if (0 | 0)
		v5 = 0xFA00000 * (0 << 8) + (0 * (unsigned __int64)0xFA00000 >> 24);
	else
		v5 = 0xFA00000 * (unsigned __int64)0 >> 24;
	*(unsigned long*)(VacOut + 20) ^= ((v5 >> 7) + 255) & 0xFFFFFF00;

	return true;
}
