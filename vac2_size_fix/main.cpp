#include <string>
#include <fstream>

#include <iostream>

//[2014-12-03 14:00:04] BVerifyInstalledFiles: resource\sourceinit.dat is -1 bytes, expected 155232
constexpr int VAC2_MODULE_SIZE = 155232; //Should be safe!

int main()
{
	auto file = std::fstream("C:/Dropbox/projects/gamehacking/vac_emulator/Release/vac2_emulator.dll", std::fstream::out | std::fstream::app | std::fstream::binary);

	if (!file)
	{
		std::cerr << "Could not open stream!" << std::endl;
		std::cin.get();
		return -1;
	}

	file.seekg(0, file.end);
	int file_size = file.tellg();


	if (file_size > VAC2_MODULE_SIZE)
	{
		return -1;
	}

	if (file_size == VAC2_MODULE_SIZE)
		return 0;

	auto dif = VAC2_MODULE_SIZE - file_size;

	for (int i = 0; i < dif; ++i)
		file << (unsigned char)0;

	file.flush();
	file.close();

	//rename file
	std::rename("C:/Dropbox/projects/gamehacking/vac_emulator/Release/vac2_emulator.dll", "C:/Dropbox/projects/gamehacking/vac_emulator/Release/sourceinit.dat");
}