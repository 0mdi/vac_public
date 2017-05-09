#pragma once
#include <string>
#include <vector>

bool DataCompare(const unsigned char* OpCodes, const unsigned char* Mask, const char* StrMask);
unsigned long FindPattern(unsigned long StartAddress, unsigned long CodeLen, unsigned char* Mask, char* StrMask, unsigned short ignore);

int __stdcall GetVACProcIndex(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, unsigned long ModuleBase);

void CheckPacketDangerous(unsigned char *VacOut, unsigned long *VacOutSize);