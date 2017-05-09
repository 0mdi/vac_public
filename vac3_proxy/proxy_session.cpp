#include "proxy_session.hpp"
#include "proxy_protocol.hpp"
#include "proxy_server.hpp"

#include "../easylogging++.h"
#include "MD5.h"
#include "detours.h"

#include <fstream>
#include <sstream>
#include <experimental/filesystem>
#include <Windows.h>

#pragma comment(lib, "detours")

struct ProcStruct
{
	unsigned long NextProc;
	unsigned long Checksum1;
	unsigned long Checksum2;
	unsigned long ProcAddress;
	unsigned long XorTable;
};

__declspec(dllimport) bool __stdcall ParseVAC3Output(const std::vector<unsigned char>& ModuleVec, int FunctionId, unsigned char *VacOut, unsigned long *VacOutSize, unsigned char *VacInput, unsigned long VacInputSize, void *ParserData, unsigned long ModuleBase);
__declspec(dllimport) std::vector<unsigned char> __stdcall DecryptVACData(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, const std::vector<unsigned char> &Encrypted, unsigned long ModuleBase, bool doXor);
__declspec(dllimport) std::vector<unsigned char> __stdcall DecryptVACIn(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, unsigned long ModuleBase);
__declspec(dllimport) std::vector<unsigned char> __stdcall EncryptVACData(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, const std::vector<unsigned char> &Decrypted, unsigned long ModuleBase, bool doXor);
__declspec(dllimport) std::vector<ProcStruct*> GetVACProcedures(const std::vector<unsigned char> &Module, unsigned long ModuleBase);
__declspec(dllimport) unsigned long __stdcall GetVACProcChecksum(const std::vector<unsigned char> &Module, const std::vector<unsigned char> &VacIn, unsigned long ModuleBase);
__declspec(dllimport) ProcStruct* __stdcall GetVACProcChecksumProc(unsigned char *Module, const std::vector<unsigned char> &VacIn, unsigned long ModuleBase);
__declspec(dllimport) bool __stdcall PreprocessModule(const std::vector<unsigned char>& ModuleVec, unsigned long ModuleBase);

proxy_session::ProcAnalyze_t proxy_session::m_trampoline = nullptr;
std::mutex proxy_session::m_mutex;
std::function<void(unsigned char*, unsigned long*)> proxy_session::m_procLambda;
bool proxy_session::m_isCrashing = false;

proxy_session::proxy_session(boost::asio::io_service& io_service)
	: m_socket(io_service)
	, m_timeout_timer(io_service)
	, m_recv_buf(sizeof(packet_header))
	, m_vac_module(nullptr)
	, m_runfunc(nullptr)
	, m_permission_granted(true)
	, m_ref_counter(0)
{}

proxy_session::~proxy_session()
{
	if (m_vac_module != nullptr)
		FreeLibrary(m_vac_module);
}

void proxy_session::start()
{
	//Set timer
	m_timeout_timer.expires_from_now(boost::posix_time::seconds(60));
	m_timeout_timer.async_wait(boost::bind(&proxy_session::handle_timeout, this, boost::asio::placeholders::error));

	boost::asio::async_read(m_socket, boost::asio::buffer(m_recv_buf, sizeof(packet_header)), boost::asio::transfer_exactly(sizeof(packet_header)), boost::bind(&proxy_session::handle_read_header, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void proxy_session::handle_timeout(const boost::system::error_code &ec)
{
	if (!ec)
	{
		//Trigger disconnect
		LOG(WARNING) << m_socket.remote_endpoint().address().to_string() << " - TIMEOUT";
		m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
		m_socket.cancel();
	}
}

void proxy_session::handle_read_header(const boost::system::error_code& ec, std::size_t bytes_transferred)
{
	if (!ec)
	{
		m_timeout_timer.cancel();

		std::cout << std::endl;

		//Check transferred bytes
		if (bytes_transferred != sizeof(packet_header))
		{
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - Could not read full packet_header!";
			delete this; //disconnect
			return;
		}

		//Verify header
		auto header = (packet_header*)m_recv_buf.data();
		auto magic = header->magic;
		auto id = header->id;
		auto body_size = header->body_size;

		if (magic != 0x1337)
		{
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - Invalid magic";
			delete this;
			return;
		}

		//Read body
		m_recv_buf.resize(header->body_size);
		boost::asio::async_read(m_socket, boost::asio::buffer(m_recv_buf, body_size), boost::asio::transfer_exactly(body_size), boost::bind(&proxy_session::handle_read, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, id));
		
		m_timeout_timer.expires_from_now(boost::posix_time::seconds(60));
		m_timeout_timer.async_wait(boost::bind(&proxy_session::handle_timeout, this, boost::asio::placeholders::error));
	}
	else
	{
		LOG(WARNING) << m_socket.remote_endpoint().address().to_string() << " - Disconnected! ERROR: " << ec.message();	
		delete this;
	}
}

void proxy_session::handle_read(const boost::system::error_code& ec, std::size_t bytes_transferred, unsigned char id)
{
	if (!ec)
	{
		m_timeout_timer.cancel();
		auto body_data = m_recv_buf.data();

		switch (id)
		{
		case vac_module_packet_id:
			handle_vac_module(body_data, bytes_transferred);
			break;
		case vac_request_id:
			handle_vac_request(body_data, bytes_transferred);
			break;
		case vac_module_split_id:
			handle_vac_split(body_data, bytes_transferred);
			break;

		default:
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - Unknown id {" << (int)id << "}";
			delete this;
			return;
		}

		m_recv_buf.resize(sizeof(packet_header));
		boost::asio::async_read(m_socket, boost::asio::buffer(m_recv_buf, sizeof(packet_header)), boost::asio::transfer_exactly(sizeof(packet_header)), boost::bind(&proxy_session::handle_read_header, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));

		m_timeout_timer.expires_from_now(boost::posix_time::seconds(60));
		m_timeout_timer.async_wait(boost::bind(&proxy_session::handle_timeout, this, boost::asio::placeholders::error));
	}
	else
	{
		LOG(WARNING) << m_socket.remote_endpoint().address().to_string() << " - Disconnected! ERROR: " << ec.message();
		delete this;
	}
}

void proxy_session::handle_write(const boost::system::error_code& ec, std::size_t bytes_transferred)
{
	if (ec)
	{
		LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - Could not write data : " << ec.message();
		m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
	}
}

std::string ExePath() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	return std::string(buffer).substr(0, pos);
}

//Shitty C&P
bool DataCompare(const BYTE* OpCodes, const BYTE* Mask, const char* StrMask)
{
	//solange bis String zuende  
	while (*StrMask)
	{
		//wenn Byte ungleich --> false  
		if (*StrMask == 'x' && *OpCodes != *Mask)
			return false;

		++StrMask;
		++OpCodes;
		++Mask;
	}

	return true;  //wenn alle Bytes gleich  
}

DWORD FindPattern(DWORD StartAddress, DWORD CodeLen, BYTE* Mask, char* StrMask, unsigned short ignore)
{
	unsigned short Ign = 0;
	DWORD i = 0;

	while (Ign <= ignore)
	{
		if (DataCompare((BYTE*)(StartAddress + i++), Mask, StrMask))
			++Ign;

		else if (i >= CodeLen)
			return 0;
	}
	return StartAddress + i - 1;
}

DWORD SizeOfPEHeader(const IMAGE_NT_HEADERS * pNTH)
{
	return (offsetof(IMAGE_NT_HEADERS, OptionalHeader) + pNTH->FileHeader.SizeOfOptionalHeader + (pNTH->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
}

std::string HashPEHeader(unsigned char* ModuleData)
{
	//Resolve Xor Table
	auto dosHeader = (PIMAGE_DOS_HEADER)ModuleData;
	auto ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader)+(dosHeader->e_lfanew));

	auto peSize = SizeOfPEHeader(ntHeader);

	return md5((char*)ntHeader, peSize);
}

void proxy_session::handle_vac_module(unsigned char* data, unsigned long size)
{
	try
	{
		auto module_packet = vac_module_packet(data, size);

		//Verify VAC Module
		LOG(INFO) << m_socket.remote_endpoint().address().to_string() << " - VAC_MODULE received! (" << std::hex << module_packet.get_module_size() << ")";

		if (module_packet.get_module_data() == nullptr)
		{
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - module_packet.get_module_data() == nullptr";

			m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
			return;
		}

		//Dump module
		std::string module_size_str;
		std::stringstream ss;

		ss << std::hex << module_packet.get_module_size();
		ss >> module_size_str;

		m_module_name = std::string("modules/VAC_") + module_size_str + std::string("_") + HashPEHeader(module_packet.get_module_data()) + ".dll";

		std::ofstream module_file(m_module_name, std::ofstream::binary | std::ofstream::trunc);

		if (module_file)
		{
			module_file.write((char*)module_packet.get_module_data(), module_packet.get_module_size());
			module_file.close();
		}
		else
		{
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << "Failed to open " << m_module_name;
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << strerror(errno);

			auto file_error_packet = vac_file_error();
			m_socket.async_send(boost::asio::buffer(file_error_packet.get_data(), file_error_packet.get_size()), boost::bind(&proxy_session::handle_write, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
			return;
		}

		//Free already running module
		if (m_vac_module != nullptr)
		{
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - Unloading running module...";

			//MemoryFreeLibrary(m_vac_module);
			FreeLibrary(m_vac_module);
			m_vac_module = nullptr;
			m_runfunc = nullptr;
		}

		//Load module into process
		m_ModuleVec = std::vector<unsigned char>{ module_packet.get_module_data(), module_packet.get_module_data() + module_packet.get_module_size() };
		//m_vac_module = MemoryLoadLibrary(module_packet.get_module_data());
		m_vac_module = LoadLibraryA(m_module_name.c_str());

		if (m_vac_module == nullptr)
		{
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - m_vac_module == nullptr";
			m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
			return;
		}

		//Get runfunc
		m_runfunc = (runfunc_t)GetProcAddress(m_vac_module, "_runfunc@20");

		if (m_runfunc == nullptr)
		{
			LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - m_runfunc == nullptr";
			m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
			return;
		}

	}
	catch (const module_exception &e)
	{
		LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - Exception: " << e.what();
		m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
	}
}

template<class Elem, class Traits>
inline void hex_dump(const void* aData, std::size_t aLength, std::basic_ostream<Elem, Traits>& aStream, std::size_t aWidth = 16)
{
	const char* const start = static_cast<const char*>(aData);
	const char* const end = start + aLength;
	const char* line = start;
	while (line != end)
	{
		aStream.width(4);
		aStream.fill('0');
		aStream << std::hex << line - start << " : ";
		std::size_t lineLength = std::min(aWidth, static_cast<std::size_t>(end - line));
		for (std::size_t pass = 1; pass <= 2; ++pass)
		{
			for (const char* next = line; next != end && next != line + aWidth; ++next)
			{
				char ch = *next;
				switch (pass)
				{
				case 1:
					aStream << (ch < 32 ? '.' : ch);
					break;
				case 2:
					if (next != line)
						aStream << " ";
					aStream.width(2);
					aStream.fill('0');
					aStream << std::hex << std::uppercase << static_cast<int>(static_cast<unsigned char>(ch));
					break;
				}
			}
			if (pass == 1 && lineLength != aWidth)
				aStream << std::string(aWidth - lineLength, ' ');
			aStream << " ";
		}
		aStream << std::endl;
		line = line + lineLength;
	}
}

inline std::string hex_cpp_dump(unsigned char* data, int length)
{
	std::ostringstream ss;

	ss << "{";

	for (int i = 0; i < length; ++i)
	{
		ss.width(2);
		ss.fill('0');
		ss << "0x" << std::hex << std::uppercase << (int)data[i];

		if (i != length - 1)
			ss << ", ";
	}

	ss << "}";
	return ss.str();
}

int __cdecl proxy_session::procHook(unsigned char *VacParam, unsigned char *VacOut, unsigned long *VacOutSizePtr)
{
	int ret = 0;

	if (!m_isCrashing)
	{
		//Call original trampoline
		ret = m_trampoline(VacParam, VacOut, VacOutSizePtr);
	}

	//Call lambda
	m_procLambda(VacOut, VacOutSizePtr);

	return ret;
}

void proxy_session::handle_vac_request(unsigned char* data, unsigned long size)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	m_trampoline = nullptr;

	LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - VAC_REQUEST received!";

	//Check module availabilty
	if (m_vac_module == nullptr || m_runfunc == nullptr)
	{
		LOG(ERROR) << m_socket.remote_endpoint().address().to_string() << " - Module not available or not correctly loaded.";
		m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
		return;
	}

	try
	{
		LOG(INFO) << "Processing data...";
		auto request = vac_request(data, size);
		LOG(INFO) << "Done!";

		int result = -1;

		
		auto hash = HashPEHeader(m_ModuleVec.data());
		m_isCrashing = hash == "1439a82ab366a8f21219eac1a56145ef"/*"f2affa09ef12f1ee15bc2534c64fa8f2"*/ || hash == "3923138b620fae3f21c0cfd6a92342ca"/*"76674b00660c3d3a6f981bb02fec58a2"*/ || hash == "564d77abef8aa8768bf66ae39ca4bced" || hash == "0b7e0a275fdd50a461fbd1e265352e66" || hash == "3244980c147202f38924b4e7cdf10eed";
		bool procCalled = false;
		bool stopSend = false;

		//Hook  ProcAnalyzeX function
		try
		{
			if (hash != "3923138b620fae3f21c0cfd6a92342ca" && hash != "13e2fa7122b8bde38870f6fc8dd559dd" && hash != "0b7e0a275fdd50a461fbd1e265352e66")
			{
				auto proc = GetVACProcChecksumProc(m_ModuleVec.data(), std::vector<unsigned char>{ request.get_parameters(), request.get_parameters() + request.get_parameters_size() }, (unsigned long)m_vac_module);

				if (proc == nullptr)
					throw std::exception("proc == nullptr");

				LOG(INFO) << "Hooking: 0x" << std::hex << proc->ProcAddress << ", Checksum: 0x" << proc->Checksum1;

				m_trampoline = (ProcAnalyze_t)DetourFunction((unsigned char*)proc->ProcAddress, (unsigned char*)procHook);

				if (!m_trampoline)
					throw std::exception("Error while hooking VAC Procedure");
			}

		}
		catch (const std::exception& e)
		{
			LOG(INFO) << m_socket.remote_endpoint().address().to_string() << " - Error while trying to grab procesdures: " << e.what();
			m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
			return;
		}

		//Generate lambda function
		m_procLambda = [this, &request, &procCalled, &stopSend, &hash](unsigned char *VacOut, unsigned long *VacOutSize)
		{
			try
			{
				procCalled = true;

				auto VacIn = std::vector<unsigned char>{ request.get_parameters(), request.get_parameters() + request.get_parameters_size() };
				
				std::ostringstream OutputBuffer;

				/*hex_dump(VacOut, *VacOutSize, OutputBuffer);
				CLOG(INFO, m_username.c_str()) << "VacOut: \n" << OutputBuffer.str();*/

				//if (!m_isCrashing)
				//{
				//	OutputBuffer.str("");
				//	OutputBuffer.clear();
					/*hex_dump(request.get_parser_data(), request.get_parser_data_size(), OutputBuffer);
					CLOG(INFO, m_username.c_str()) << "ParserData: \n" << OutputBuffer.str();*/
				//}

				//Now Parse data and make it legit
				ParseVAC3Output(m_ModuleVec, request.get_function_id(), VacOut, VacOutSize, request.get_parameters(), request.get_parameters_size(), request.get_parser_data(), (unsigned long)m_vac_module);

				/*OutputBuffer.str("");
				OutputBuffer.clear();
				hex_dump(VacOut, *VacOutSize, OutputBuffer);
				CLOG(INFO, m_username.c_str()) << "Parsed: \n" << OutputBuffer.str();*/
			}
			catch (const std::exception& e)
			{
				std::ostringstream OutputBuffer;

				hex_dump(VacOut, *VacOutSize, OutputBuffer);
				LOG(INFO) << "VacOut: \n" << OutputBuffer.str();

				OutputBuffer.str("");
				OutputBuffer.clear();
				hex_dump(request.get_parser_data(), request.get_parser_data_size(), OutputBuffer);
				LOG(INFO) << "ParserData: \n" << OutputBuffer.str();

				stopSend = true;
				LOG(INFO) << m_socket.remote_endpoint().address().to_string() << " - Error while parsing VAC3 Data: " << e.what();
				LOG(INFO) << m_socket.remote_endpoint().address().to_string() << " - Hash: " << HashPEHeader(m_ModuleVec.data());
				//m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect

				std::string new_module = m_username + "_" + HashPEHeader(m_ModuleVec.data()) + ".new_module";

				//Register new module immediately
				std::ofstream new_module_file("C:/Users/Administrator/Desktop/omdisserver/auth_server/" + new_module);

				//Cannot create file whut
				if (!new_module_file)
				{
					LOG(FATAL) << "Cannot create maintenace file!";
					return;
				}

				new_module_file.close();

				LOG(WARNING) << "Registered new module!";

				//Send new module packet
				auto new_module_packet = vac_new_module();
				
				m_socket.async_send(boost::asio::buffer(new_module_packet.get_data(), new_module_packet.get_size()), boost::bind(&proxy_session::handle_write, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));

				m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
				return;
			}
		};


		//Generate response and trigger hook proc
		/*std::cout << "vac in size: 0x" << std::hex << request.get_parameters_size() << std::endl;
		std::cout << "out size: 0x" << std::hex << *request.get_result_size_ptr() << std::endl;*/

		//Preprocess
		LOG(INFO) << "Preprocessed: " << PreprocessModule(m_ModuleVec, (unsigned long)m_vac_module);

		if (hash != "3923138b620fae3f21c0cfd6a92342ca" && hash != "13e2fa7122b8bde38870f6fc8dd559dd" && hash != "0b7e0a275fdd50a461fbd1e265352e66" && hash != "3244980c147202f38924b4e7cdf10eed")
		{
			*request.get_result_size_ptr() = 0x1000;
			result = m_runfunc((int)request.get_function_id(), (int)request.get_parameters(), (int)request.get_parameters_size(), (int)request.get_result(), (int)request.get_result_size_ptr());
		}
		else
		{
			m_procLambda(request.get_result(), (unsigned long*)request.get_result_size_ptr());
		}

		LOG(INFO) << "runfunc result: " << result;

		if(m_trampoline)
			DetourRemove((unsigned char*)m_trampoline, (unsigned char*)procHook);

		if (!procCalled)
		{
			throw std::exception("procCalled is false!");
		}

		if (stopSend)
		{
			LOG(INFO) << "VacIn (C++): \n" << hex_cpp_dump(request.get_parameters(), request.get_parameters_size());
		}


		if (!stopSend)
		{
			//Send response
			auto response = vac_response(request.get_function_id(), *request.get_result_size_ptr(), request.get_result());

			m_socket.async_send(boost::asio::buffer(response.get_data(), response.get_size()), boost::bind(&proxy_session::handle_write, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));

			LOG(INFO) << m_socket.remote_endpoint().address().to_string() << " - VAC_RESPONSE sent! (0x" << std::hex << *request.get_result_size_ptr() << ")";

			m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
		}
	}
	catch (const std::exception& e)
	{
		LOG(INFO) << m_socket.remote_endpoint().address().to_string() << " - Error: " << e.what();
		m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
		return;
	}
}

void proxy_session::handle_vac_split(unsigned char * data, unsigned long size)
{
	try
	{
		auto split_packet = vac_module_split(data, size);

		if (split_packet.m_ref_counter == 0)
		{
			m_ModuleVec.clear();
			m_ref_counter = 0;
		}

		if (split_packet.m_ref_counter != m_ref_counter)
		{
			std::cout << "m_ref_counter: " << m_ref_counter << std::endl;
			std::cout << "split_packet.m_ref_counter: " << split_packet.m_ref_counter << std::endl;
			throw std::exception("Invalid ref_counter");
		}

		std::cout << "SPLIT PACKET " << m_ref_counter << " RECEIVED! (" << split_packet.m_split_size << ")" << std::endl;
		std::cout << m_ModuleVec.size() << "/" << split_packet.m_total_size << std::endl;

		++m_ref_counter;
		auto old_size = m_ModuleVec.size();
		m_ModuleVec.resize(old_size + split_packet.m_split_size);
		std::copy(split_packet.m_split_data, split_packet.m_split_data + split_packet.m_split_size, m_ModuleVec.begin() + old_size);

		//Full module received
		if (split_packet.m_total_size == m_ModuleVec.size())
		{
			std::cout << "FULL PACKET RECEIVED!" << std::endl;

			//Decrypt module_data now
			//xor_encrypt_decrypt("\xDE\xAD", 2, (char*)m_ModuleVec.data(), m_ModuleVec.size());

			std::cout << "DECRYPTED" << std::endl;

			std::cout << "Creating fake packet..." << std::endl;
			auto tmp_packet = vac_module_packet_tmp(split_packet.m_session_key, m_ModuleVec.data(), m_ModuleVec.size());

			std::cout << "Processing fake packet..." << std::endl;
			handle_vac_module(tmp_packet.get_data(), tmp_packet.get_size());
			std::cout << "everything done" << std::endl;
		}
	}
	catch (const std::exception &e)
	{
		std::cout << " - Exception: " << e.what() << std::endl;
		m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both); //disconnect
	}
}
