#pragma once
#include <boost/bind.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>

#include <vector>
#include <string>
#include <mutex>

#include "MemoryModule.h"


class proxy_session
{
public:
	typedef int (__stdcall* runfunc_t)(int, int, int, int, int);
	typedef int(__cdecl* ProcAnalyze_t)(unsigned char*, unsigned char*, unsigned long*);

	proxy_session(boost::asio::io_service& io_service);
	~proxy_session();

	boost::asio::ip::tcp::socket& get_socket()
	{
		return m_socket;
	}

	void start();

private:
	void handle_read_header(const boost::system::error_code& ec, std::size_t bytes_transferred);
	void handle_read(const boost::system::error_code& ec, std::size_t bytes_transferred, unsigned char id);
	void handle_write(const boost::system::error_code& ec, std::size_t bytes_transferred);

	void handle_timeout(const boost::system::error_code &ec);

	void handle_vac_module(unsigned char* data, unsigned long size);
	void handle_vac_request(unsigned char* data, unsigned long size);
	void handle_vac_split(unsigned char* data, unsigned long size);

	static int __cdecl procHook(unsigned char *VacParam, unsigned char *VacOut, unsigned long *VacOutSizePtr);

private:
	boost::asio::io_service m_io_service;
	boost::asio::ip::tcp::socket m_socket;
	boost::asio::deadline_timer m_timeout_timer;

	std::vector<unsigned char> m_recv_buf;

	//HMEMORYMODULE m_vac_module;
	HMODULE m_vac_module;
	runfunc_t m_runfunc;

	unsigned int m_ref_counter;
	std::vector<unsigned char> m_ModuleVec;
	std::string m_module_name;

	static bool m_isCrashing;
	static ProcAnalyze_t m_trampoline;
	static std::mutex m_mutex;

	static std::function<void(unsigned char*, unsigned long*)> m_procLambda;
};