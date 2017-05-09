#include "Blacklist.hpp"

std::string BlacklistProcessName[] =
{
	"omdis",
	"OmdisCheats",
	"csgo_hack",
	"idaq.exe",
	"cheatengine-i386.exe",
	"UnknownInject.exe",
	"ocs",
	"Local\Temp",
	"HazeDumper",
	"Wireshark.exe",
	"AntTweakBar",
	"lua5.1",
	"luabind",
	"cheat_files",
	"VMProtect",
	"Pubindebiyabindi",
	"unknowncheats.me"
};

unsigned long BlacklistChecksums[] =
{
	0x3948d561, //omdis.exe
	0x3c3ede5e
};

std::string Blacklist6e00h[Blacklist6e00hMax][2] =
{
	{ "HazeDumper.bin", "" },
	{ "ocs", ".tmp" },
	{ "csgo_hack.exe", "" },
	{ "dis_cheats", "" },
	{ "omdis" ""},
	{ "cheatengine-i386.exe", ""},
	{ "AntTweakBar", ""},
	{ "lua5.1", ""},
	{ "luabind", ""}
};