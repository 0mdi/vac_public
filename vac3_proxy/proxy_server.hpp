#pragma once
#include <boost/bind.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include "proxy_session.hpp"

#define EXTENDED_LOGS "extended_logs"

class proxy_server
{
public:
	proxy_server(boost::asio::io_service& io_service, short port);
	~proxy_server();

	void start_accept();

private:
	void handle_accept(proxy_session* session, const boost::system::error_code& ec);


private:
	boost::asio::io_service& m_io_service;
	boost::asio::ip::tcp::acceptor m_acceptor;
};