#pragma once
#include <boost/bind.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>

class proxy_client
{
public:
	proxy_client()
		: m_connected(false)
	{
		m_io_service = new boost::asio::io_service();
		m_socket = new boost::asio::ip::tcp::socket(*m_io_service);
	}

	~proxy_client()
	{

	}

	bool connect(std::string ip, std::string port)
	{
		try
		{
			boost::system::error_code ec;
			boost::asio::io_service io_service;

			boost::asio::ip::tcp::resolver resolver(io_service);
			boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), ip, port);
			auto iterator = resolver.resolve(query);

			boost::asio::connect(*m_socket, iterator, ec);

			if (ec)
				return false;

			m_connected = true;
			return true;
		}
		catch (const std::exception& e)
		{
			return false;
		}
	}

	bool is_connected()
	{
		return m_connected;
	}

	bool send_packet(unsigned char* data, unsigned long size)
	{
		boost::system::error_code ec;
		boost::asio::write(*m_socket, boost::asio::buffer(data, size), boost::asio::transfer_all(),/*boost::asio::transfer_exactly(size),*/ ec);

		if (ec)
		{
			if(ec == boost::asio::error::connection_aborted
			|| ec == boost::asio::error::connection_refused
			|| ec == boost::asio::error::not_connected
			|| ec == boost::asio::error::eof)
				m_connected = false;

			return false;
		}

		return true;
	}

	unsigned long recv_packet(unsigned char* buf, unsigned long size)
	{
		boost::system::error_code ec;
		unsigned long bytes_transferred = boost::asio::read(*m_socket, boost::asio::buffer(buf, size), boost::asio::transfer_at_least(sizeof(packet_header)), ec);

		if (ec)
		{
			m_connected = false;
			return 0;
		}

		return bytes_transferred;
	}

private:
	boost::asio::io_service* m_io_service;
	boost::asio::ip::tcp::socket* m_socket;

	bool m_connected;
};