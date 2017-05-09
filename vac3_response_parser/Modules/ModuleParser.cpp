#include "ModuleParser.hpp"
#include "../Hash/Hash.hpp"
#include "Blacklist.hpp"
#include "../ModuleUtils.hpp"

#include <algorithm>
#include <iterator>
#include <iostream>
#include <Windows.h>



bool ModuleParser::ParseModule(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase)
{
	bool CorrectedOutput = false;

	if (ModuleVec.empty())
		throw std::exception("ModuleVec is empty");

	switch (str2int(HashPEHeader((unsigned char*)ModuleVec.data()).data()))
	{
	case str2int("42d27a6dd6789b14f03305996ae16fdc"):
	case str2int("9c78b6e194a8e383f9180133aa54aa33"):
	case str2int("7af912acc1851978c4dcd1d3d1b476fc"):
	case str2int("46ee7a9158a7b3afdfa4206568aaff49"):
	case str2int("954bf3dd7467032c786d429ff10c5e3a"):
	case str2int("6d686c4c9ed5eaa636376465c6e0a8b5"):
	case str2int("68c96296f491791114b1d0316b78b406"):
	case str2int("02dabcc999e57d3128358a4d75a7064a"):
	case str2int("87f14dc1ee882092f1dc79e3725f10c4"):
	case str2int("e331b4cf99b12ed689918d22fb56cc9b"):
	case str2int("022d25958e1077aea01e9e47187ec713"):
		CorrectedOutput = Module10c00h::ParseOutput(ModuleVec, FunctionId, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	//Init Module
	case str2int("31d0e6ffdbfde020a7644309c4a2b697"):
	case str2int("ef1e2e7a7fef71e1e9558c9077cafb0c"):
	case str2int("ef6df49b53cc40f2850290aabb1a76d9"):
	case str2int("374b378c1fd6f4b5997e194082b36048"):
	case str2int("a26a7c77a7ddb8ae3924d1c7a9c345ae"):
	case str2int("e6622f49924d36fec9afa92fa94d2648"):
	case str2int("f318705f329e29579d2924c2bc994d9f"): // 02.11.2016
	case str2int("862afc8c139b1df483d38d0ad66f7148"): // 09.11.2016
	case str2int("b62ef08ef8d3b0c2c4a6167ce819144f"): // 26.11.2016
	case str2int("4fc312410ffdaf7259ec449abe2e0d56"): //19.04.2017
		CorrectedOutput = Module8600h::ParseOutput(ModuleVec, FunctionId, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	//steam_singleton_
	case str2int("2129ce224eb35781805c600ee57b6394"):
	case str2int("469d99ea1bbcea895529dc8a3640f716"):
	case str2int("b2d7e33b0c18fbdf6c6fdf68afb680c2"):
	case str2int("a4fc2caf461532bcb67d5c93552afb33"):
	case str2int("ba83769dded44562c3d3f6fca271095a"): //26.11.2016
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//IP & MAC Addr module
	case str2int("f0a76b704e2c10ef9b29a4ae12ab28b8"):
	case str2int("ef8f74fd3288757d1ebb2e63fc5504c1"):
	case str2int("fd3058b13bcf7597d7ababdcf5b89ccc"):
	case str2int("ef4b43068d8535651da2afce3ce01203"):
	case str2int("bd9529f4eabf3cd269097738c9596284"):
	case str2int("4462320e8dffcdf986392200f9a38039"): //09.11.2016
	case str2int("3d3164d6ce10cc5fa4c700015c72101d"): //26.11.2016
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	case str2int("4dc91db76ca859f798d59f2f2f992ab4"):
	case str2int("0b3788d1380d3dfc340aa9769c4af496"):
	case str2int("a2c305d5c388e79e425433cf1a53cfa8"):
	case str2int("43193f134786b692b54e6d142e0d67b5"): //09.11.2016
		CorrectedOutput = Module9a00h::ParseOutput(ModuleVec, FunctionId, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	//Operating System
	case str2int("30623c2f01515467ea6a89848b3beb5e"):
	case str2int("249a65ee366e870ca66df3a4bfd9fdc2"):
	case str2int("c88a23a8b0b2e903b36f5871a3b45518"):
	case str2int("3a0b7a4e13d99a62903cb0391a4e36cc"):
	case str2int("ddb631fde9f2e5a5e2a9c00350c1787e"): //09.11.2016
	case str2int("c4f6c0f46e5f87cc8c3f5c03e516a5ac"): //26.11.2016
	case str2int("15bd61ceb0d8db407e90b9b2bc6dc1ea"): //26.12.2016 - Added a few more infos
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//Processor Type, Manufactor
	case str2int("dacba48351e8027af12f655d7744af3c"):
	case str2int("dff41d13359f14db2aed539563c37f68"):
	case str2int("76891fa84ec8f57512cf1412f3dab00f"):
	case str2int("db76faf36b2c4f4140898850ddf8e31b"):
	case str2int("6529e72bd13f5a68182bc31ded87d179"): //10.11.2016
	case str2int("537bd8e88e8719ddd764e57131a6a68b"): //29.11.2016
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//Dumps all drivers
	case str2int("4a08db06eb9eeced5a28e92d46a037ee"):
	case str2int("7f1dabaeb4bf83030497ec69b2e32ef8"):
	case str2int("8ca97a4895846f9e1d3dfb8e3bceeca3"):
	case str2int("5da6069fbdf7f91e3c740610a4ac7a80"):
	case str2int("7ac0ae806b8856f6b9283257998282b3"):
	case str2int("e0ceca3a4f238d30cdd2fd71782c0c57"): //09.11.2016
	case str2int("7f453ce46b858c20c43de6b45610a211"): //26.11.2016
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//Scan for drivers using vendor & device id
	case str2int("26a33fd235aaccf1e4631e5d33f12497"):
	case str2int("4004639a282aa22f761da2e7c448e32b"): //28.11.2016
		memcpy(VacOut, ParserData, 0x1400);
		*VacOutSize = 0xF0;
		break;

	//Scan for drivers using event log
	case str2int("ac81ca4568816d61cfcacc5488d63f65"):
	case str2int("4aa04ffa1a763e6fd90498286aaaada7"): //03.01.2017
		memcpy(VacOut, ParserData, 0x1400);
		break;

	//Internal CSGO Check Module
	case str2int("f2affa09ef12f1ee15bc2534c64fa8f2"):
	case str2int("1439a82ab366a8f21219eac1a56145ef"):
	case str2int("564d77abef8aa8768bf66ae39ca4bced"):
	case str2int("0b7e0a275fdd50a461fbd1e265352e66"):
	case str2int("3244980c147202f38924b4e7cdf10eed"): //02.12.2016
		CorrectedOutput = Module6200h::ParseOutput(FunctionId, VacOut, VacOutSize);
		break;

	//Dump opened handles
	case str2int("88875078178b429b56bbe2c1a68cd0ef"):
	case str2int("737fc2d1853cb70646e069dc323ff6c5"):
	case str2int("97e9ac86ec432ed7398014ed57a1149d"):
	case str2int("55225482bedaae397ec1ad85204df4bf"):
	case str2int("dac92ff78f2234cdcdfa34be7003e365"):
	case str2int("567c5d02977eef81a87eae352f83b799"):
	case str2int("6b9a703bf14ea905dfd43d192880c72d"): //09.11.2016
		CorrectedOutput = Module6e00h::ParseOutput(FunctionId, VacOut, VacOutSize, ParserData);
		break;

	//Crashing handle module
	case str2int("dd12a7451ae1f92cfcd73628165894d8"):
		CorrectedOutput = Module5e00::ParseOutput(ModuleVec, FunctionId, VacOut, VacOutSize, VacInput, VacInputSize, ModuleBase);
		break;


	case str2int("76674b00660c3d3a6f981bb02fec58a2"):
	case str2int("3923138b620fae3f21c0cfd6a92342ca"):
	case str2int("13e2fa7122b8bde38870f6fc8dd559dd"):
		CorrectedOutput = Module1c400h::ParseOutput(VacOut, VacOutSize);
		break;


	//Sends Page Protect & Alloc Protect of current process to server
	case str2int("b6d1e60657e598f8bddb66b69877aaf4"):
	case str2int("3383a979f8c5f0aaa68d86bdfdd1abd6"):
	case str2int("f09a7f72e3a9ccf88a87dda4d8a68992"):
		CorrectedOutput = Module8200h::ParseOutput(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	//Dumps open handles too?
	case str2int("40eadf7c55f84423040e5c70b4685c12"):
	case str2int("38ad58fd4fa68c0476e5ba94512c562a"):
	case str2int("7b3fce02748fe7103f8c2d08ea3fcfdd"): //13.11.2016
		CorrectedOutput = Module7800h::ParseOutput(FunctionId, VacOut, VacOutSize, ParserData);
		break;

	case str2int("21a1d56e23fb183223ba3905732e6d84"):
		break;

	//Window Enumeration Module. Cleaned everything on client PC with preprocessing
	case str2int("8d950d606675e1ad21fa5d51cc8dfbf2"):
	case str2int("8c166437ff9327e7081b97c2808ff6d9"):
	case str2int("92378b5671a0387705da0defdd7dd5fc"): //26.11.2016
		memcpy(VacOut, ParserData, *VacOutSize);
		break;
	
	//Memory dumper -> takes in ProcessID
	case str2int("c14d300e2978826b5e0d1b9e50bc6631"):
	case str2int("4df54595e8a9a8f49e60377e969e816b"):
	case str2int("766fda5a9e5f0aa75f065f5292fc0ae4"): //09.11.2016
	case str2int("cfd9138c6ed080b44a0c15c730f21272"): //16.11.2016
	case str2int("a64fc624f5be2f1d4b0e862d577908be"): //26.11.2016
	case str2int("520a6c5146fe54196dc00193ef56d2e6"): //26.11.2016
	case str2int("9f41c2cb20aaa33896386ea8748d98ab"): //21.04.2017
		//memcpy(VacOut, ParserData, *VacOutSize);
		CorrectedOutput = Modulec000::ParseOutput(VacOut, VacOutSize, ParserData);
		break;

	//Special Process Dump Only Module
	case str2int("44eb01e6f227fa894807169cf2d47377"):
	case str2int("8f5e338c235fb79f99c123c2bfc35b89"): //09.11.2016
	case str2int("adf055372fac36860e2faf1503343d3a"): //17.11.2016
	case str2int("9d1b58e5b25a10b7e6a5605e12db5dc8"): //13.03.2017
		CorrectedOutput = Module6200_2::ParseOutput(ModuleVec, FunctionId, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	//Special DLL dump module
	case str2int("93029e08f4309c4aa2bd364f449f6fe0"):
	case str2int("84ad052e2ee1922e6e5294a58a00a906"): //09.11.2016
	case str2int("99ab1432269a92b5b813fc95905cf550"): //26.11.2016
		CorrectedOutput = Module10c00h::ParseFunction4_2(VacOut, VacOutSize, ParserData);
		break;

	//Steam related stuff with steamservice.dll & so on
	case str2int("a09f644ecdd847430b01c79ac38dbc20"):
	case str2int("fd1be02b0ca3ac59837c4345b14eb340"): // 26.11.2016
		CorrectedOutput = Module8000::ParseOutput(ModuleVec, FunctionId, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	//Completely dumps a process but encrypted (ProcessID given by server)
	case str2int("5e5682f6113df946f42337406cc222c9"): //13.11.2016
		memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//Module_MemoryDumper 
	case str2int("ad37327cc2215d1e8a8e7bff9d2ce276"):
		*VacOutSize = 4096;
		*(uint32_t*)(VacOut + 16) = 78;
		//memcpy(VacOut, ParserData, *VacOutSize);
		break;

	//Module_UserEnv
	case str2int("d1309800eceaba37ce109079d0697a05"): //26.12.2016
		CorrectedOutput = ModuleUserEnv::ParseOutput(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;
	
	//Module_FileSystemCtrl
	case str2int("d4e00c426b0e9c8a62a42e90cb9c8750"): //26.12.2016
		CorrectedOutput = ModuleFileSystemCtrl::ParseOutput(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;
	
	//Module_MappedProcessHandles
	case str2int("e92603f937852dde3b575e9867c19434"): //04.01.2017
		CorrectedOutput = ModuleMappedProcessHandles::ParseOutput(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	//Module_ProcessHash
	case str2int("d1dcb4d1180a1551bdd82e5e067eac7e"): //16.01.2017
		CorrectedOutput = ModuleProcessHash::ParseOutput(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	//Module_HandleInvestigator
	case str2int("329954951b9757bedf641c995a8b1465"): //01.02.2017520a6c5146fe54196dc00193ef56d2e6
		CorrectedOutput = ModuleHandleInvestigator::ParseOutput(ModuleVec, VacOut, VacOutSize, VacInput, VacInputSize, ParserData, ModuleBase);
		break;

	default:
		throw std::exception("Not implemented.");
	}

	//Check for bad strings - throws std::exception if packet is dangerous
	CheckPacketDangerous(VacOut, VacOutSize);

	return CorrectedOutput;
}
