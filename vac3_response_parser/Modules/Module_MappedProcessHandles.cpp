#include "ModuleParser.hpp"

#include "../ModuleUtils.hpp"

bool ModuleMappedProcessHandles::ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool Corrected = false;
	int Index = GetVACProcIndex(ModuleVec, std::vector<unsigned char>{ VacInput, VacInput + VacInputSize }, ModuleBase);

	switch (Index)
	{
	case 0:
		Corrected = ParseFunction1(VacOut, VacOutSize, ParserData);
		break;

	default:
		throw std::exception(("Undefined Proc requested: " + std::to_string(Index)).c_str());
	}

	return Corrected;
}

bool ModuleMappedProcessHandles::ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData)
{
	//ParserData is relevant
	memcpy(VacOut, ParserData, 0xFFF);

	struct SProcessInfo
	{
		int time0;
		int time1;
		unsigned long PID;
		unsigned long volumeNo;
		unsigned long fileIndexLo;
		unsigned long fileIndexHi;
		unsigned long grantedAccess;
		unsigned long flags;
		unsigned long long threadStart;
		char FileName[0x18];
	};

	//Extract SProcessInfo Array
	SProcessInfo Info[0x3F];
	SProcessInfo InfoClean[0x3F];
	memset(InfoClean, 0, sizeof(Info));

	memcpy(Info, VacOut + 0x40, sizeof(Info));

	//Copy everything that's clean into InfoClean
	int RemovedParts = 0;
	for (int i = 0, j = 0; i < sizeof(Info) / sizeof(Info[0]); ++i)
	{
		//No filename? It must be clean!
		if (!Info[i].FileName)
		{
			memcpy(&InfoClean[j], &Info[i], sizeof(Info[i]));
			++j;
			continue;
		}
		
		try
		{
			unsigned char *FileName = (unsigned char*)Info[i].FileName;
			unsigned long Length = strlen((char*)FileName);

			CheckPacketDangerous(FileName, &Length);

			//Clean
			memcpy(&InfoClean[j], &Info[i], sizeof(Info[i]));
			++j;
			continue;
		}
		catch (const std::exception&)
		{
			//Dangerous so skip
			++RemovedParts;
			continue;
		}
	}

	//Fix Count
	*(int*)(VacOut + 0x20) -= RemovedParts;

	//Overwrite Array
	memcpy(VacOut + 0x40, InfoClean, sizeof(InfoClean));

	return true;
}