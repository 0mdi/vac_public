#pragma once
#include <exception>
#include <vector>

class Preprocessor
{
public:
	static bool PreprocessBegin(const std::vector<unsigned char>& ModuleVec, unsigned long ModuleBase, unsigned char *VacParam, unsigned char *VacOut, unsigned long *VacOutSizePtr);
	static void PreprocessEnd(const std::vector<unsigned char>& ModuleVec);
};