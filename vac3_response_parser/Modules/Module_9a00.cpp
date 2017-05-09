#include "ModuleParser.hpp"

#include "../ModuleUtils.hpp"
#include "Blacklist.hpp"

bool Module9a00h::ParseFunction2(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	//Loop through BlacklistProcessName
	for (auto blacklisted : BlacklistProcessName)
	{
		std::string mask;

		for (int i = 0; i < blacklisted.length(); ++i)
			mask += 'x';

		unsigned long it = 0;

		do
		{
			it = FindPattern((unsigned long)VacOut, 0x1000, (unsigned char*)blacklisted.c_str(), (char*)mask.c_str(), 0);

			if (it)
			{
				auto end = it + strlen((char*)it);
				auto begin = it - 0x40;
				auto size = end - begin;

				memset((void*)begin, 0x00, size);
			}
		} while (it);
	}

	return true;
}

bool Module9a00h::ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;

	auto index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	//switch (index)
	//{
	//case 1:
		Corrected = ParseFunction2(VacOut, VacOutSize, ParserData);
	//	break;

	//default:
	//	throw std::exception(("Undefined Proc requested: " + std::to_string(index)).c_str());
	//}

	return Corrected;
}