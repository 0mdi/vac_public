#include <exception>

#include "proxy_server.hpp"
#include "../easylogging++.h"

std::string ExePath2() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	return std::string(buffer).substr(0, pos);
}

proxy_server::proxy_server(boost::asio::io_service& io_service, short port)
	: m_io_service(io_service)
	, m_acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
{
	//Setup pundebiyabindi logging
	auto instance_logger = el::Loggers::getLogger(EXTENDED_LOGS);
	el::Configurations logger_config;
	logger_config.setToDefault();

	logger_config.set(el::Level::Info,
		el::ConfigurationType::ToFile, "true");
	logger_config.set(el::Level::Warning,
		el::ConfigurationType::ToFile, "true");
	logger_config.set(el::Level::Error,
		el::ConfigurationType::ToFile, "true");
	logger_config.set(el::Level::Fatal,
		el::ConfigurationType::ToFile, "true");

	std::string file_path = (ExePath2() + "/extended_logs.txt");
	logger_config.set(el::Level::Info,
		el::ConfigurationType::Filename, file_path);
	logger_config.set(el::Level::Warning,
		el::ConfigurationType::Filename, file_path);
	logger_config.set(el::Level::Error,
		el::ConfigurationType::Filename, file_path);
	logger_config.set(el::Level::Fatal,
		el::ConfigurationType::Filename, file_path);

	el::Loggers::reconfigureLogger(EXTENDED_LOGS, logger_config);
}

proxy_server::~proxy_server()
{

}

void proxy_server::start_accept()
{
	proxy_session* session = new proxy_session(m_io_service);

	m_acceptor.async_accept(session->get_socket(),
		boost::bind(&proxy_server::handle_accept, this, session,
		boost::asio::placeholders::error));

	LOG(INFO) << "Server started! (" << m_acceptor.local_endpoint().address().to_string() << ")";
}

void proxy_server::handle_accept(proxy_session* session, const boost::system::error_code& ec)
{
	if (!ec)
	{
		LOG(INFO) << "New connection established! - " << session->get_socket().remote_endpoint().address().to_string();

		session->start();
		auto new_session = new proxy_session(m_io_service);
		m_acceptor.async_accept(new_session->get_socket(),
			boost::bind(&proxy_server::handle_accept, this, new_session,
			boost::asio::placeholders::error));
	}
	else
	{
		delete session;
	}
}