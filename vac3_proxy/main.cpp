#include <boost/asio.hpp>
#include <Windows.h>

#include "proxy_server.hpp"
#include "../easylogging++.h"


_INITIALIZE_EASYLOGGINGPP

int main()
{
	SetConsoleTitleA("VAC3 Proxy Server (c) Omdihar");

	el::Loggers::reconfigureAllLoggers(el::ConfigurationType::Format, "%datetime %level : %msg");
	el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
	el::Loggers::addFlag(el::LoggingFlag::LogDetailedCrashReason);

	LOG(INFO) << "VAC3_Proxy (c) Omdihar";

	boost::asio::io_service io_service;
	proxy_server server(io_service, 1337);
	server.start_accept();

	while (true)
	{
		try
		{
			boost::system::error_code ec;
			io_service.run_one(ec);

			if (ec)
			{
				LOG(ERROR) << "Error in main_loop! | " << ec.message();
			}
		}
		catch (const std::exception &e)
		{
			LOG(ERROR) << "Exception in main_loop! | " << e.what();
		}
	}

	LOG(FATAL) << "Terminating :(!";
}