#pragma once
#include <vector>

class Module_MemoryDumper
{
public:
	static bool Preprocess(const std::vector<unsigned char>& ModuleVec, unsigned long ModuleBase, unsigned char *VacParam, unsigned char *VacOut, unsigned long *VacOutSizePtr);
};