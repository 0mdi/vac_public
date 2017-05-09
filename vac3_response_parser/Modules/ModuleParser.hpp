#pragma once
#include <exception>
#include <vector>

class ModuleParser
{
public:

	class ParseException : public std::exception
	{};

	static bool ParseModule(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);
};

class Module8600h
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

private:
	static bool ParseFunction4(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class Module8a00h
{
public:
	static bool ParseOutput(int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

private:
	static bool ParseFunction4(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class Moduleee00h
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

	static bool ParseFunction4_3(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData);

};

class Modulea800h
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

private:
	static bool ParseFunction4_1(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
	static bool ParseFunction4_2(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
	static bool ParseFunction4_3(unsigned char *VacInput, unsigned long VacInputSize, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class Module10c00h
{

public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);
	static bool Preprocess(unsigned long ModuleBase);

	static bool ParseFunction4_2(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
	static bool ParseFunction4_3(unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData);
	static bool ParseFunction4_4_new(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
	static bool ParseFunction4_4(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData);

	typedef int(__fastcall *HashString_t)(char*, int);
	static HashString_t HashStringOrig;

	static int __fastcall HashStringHook(char *String, int Length);

};

class Module6200h
{
public:
	static bool ParseOutput(int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize);

private:
	static bool ParseFunction4(unsigned char *VacOut, unsigned long *VacOutSize);
};

class Module6e00h
{
public:
	static bool ParseOutput(int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);

private:
	static bool ParseFunction4(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class Module1c400h
{
public:
	static bool ParseOutput(unsigned char *VacOut, unsigned long *VacOutSize);

private:
	static bool ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize);
};

class Module8200h
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

};

class Module7800h
{
public:
	static bool ParseOutput(int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);

private:
	static bool ParseFunction4(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);

	static void Parser7800(unsigned char *TestList, unsigned long TestListSize);
	static void RemoveBlock(unsigned char *TestList, unsigned long TestListSize, unsigned char *Block);
	static unsigned char* GetBlock(unsigned char* start, unsigned char* end, const std::string& blacklisted);
};

class Module9a00h
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

	static bool ParseFunction2(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class Module6200_2
{

public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);
	static bool Preprocess(unsigned long ModuleBase);
};

class Module8000
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

private:
	static bool ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class Module5e00
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, unsigned long ModuleBase);

private:
	static bool ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize);
};

class Modulec000
{
public:
	static bool ParseOutput(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class ModuleUserEnv
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

private:
	static bool ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacIn, unsigned long VacInputSize, void *ParserData);
	static bool ParseFunction3(unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacIn, unsigned long VacInputSize, void *ParserData);
};

class ModuleFileSystemCtrl
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);

private:
	static bool ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class ModuleMappedProcessHandles
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);
private:
	static bool ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class ModuleProcessHash
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);
private:
	static bool ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};

class ModuleHandleInvestigator
{
public:
	static bool ParseOutput(const std::vector<unsigned char>& ModuleVec, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);
private:
	static bool ParseFunction1(unsigned char *VacOut, unsigned long *VacOutSize, void *ParserData);
};