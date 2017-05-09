#pragma once
#include <exception>
#include <vector>

class Preprocessor
{
public:
	class PreprocessorException : public std::exception
	{};

	static bool Preprocess(const std::vector<unsigned char>& ModuleVec, unsigned long ModuleBase);
};