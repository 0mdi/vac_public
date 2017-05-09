#include "Preprocessor.hpp"

#include "../Hash/Hash.hpp"

#include "../Modules/ModuleParser.hpp"
#include "../ModuleUtils.hpp"

bool Preprocessor::Preprocess(const std::vector<unsigned char>& ModuleVec, unsigned long ModuleBase)
{
	bool Preprocessed = false;

	if (ModuleVec.empty())
		throw std::exception("ModuleVec is empty");

	
	//Create Hash
	auto hash = str2int(HashPEHeader((unsigned char*)ModuleVec.data()).data());

	switch (hash)
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
	//case str2int("44eb01e6f227fa894807169cf2d47377"):
		Preprocessed = Module10c00h::Preprocess(ModuleBase);
		break;

	//Process dump
	case str2int("44eb01e6f227fa894807169cf2d47377"):
	case str2int("8f5e338c235fb79f99c123c2bfc35b89"): //09.11.2016
	case str2int("adf055372fac36860e2faf1503343d3a"): //17.11.2016
	case str2int("9d1b58e5b25a10b7e6a5605e12db5dc8"): //13.03.2017
		Preprocessed = Module6200_2::Preprocess(ModuleBase);
		break;

	//DLL dump
	case str2int("93029e08f4309c4aa2bd364f449f6fe0"):
	case str2int("84ad052e2ee1922e6e5294a58a00a906"):
		Preprocessed = Module10c00h::Preprocess(ModuleBase);
		break;
	}

	return Preprocessed;
}