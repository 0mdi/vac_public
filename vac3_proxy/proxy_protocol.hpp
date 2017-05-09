#pragma once
#include "NBinaryStream.hpp"
#include "xor_encryption.hpp"

#include <iostream>

enum packet_id : unsigned char
{
	vac_module_packet_id,
	vac_request_id,
	vac_response_id,
	vac_module_split_id,
	vac_new_module_id,
	vac_file_error_id,
};

struct packet_header
{
	unsigned short magic;
	packet_id id;
	unsigned long body_size;
};

class base_packet
{
public:
	base_packet()
		: m_buffer(nullptr)
	{}

	virtual ~base_packet()
	{
		if (m_buffer)
			delete m_buffer;
	}

	unsigned char* get_data()
	{
		if (m_buffer == nullptr)
			return nullptr;

		return m_buffer->data();
	}

	unsigned long get_size()
	{
		if (m_buffer == nullptr)
			return -1;

		return m_buffer->size();
	}

protected:
	Narea::NBaseBinaryStream::Buffer* m_buffer;
};

class module_exception : public std::exception
{
public:
	module_exception(std::string e)
		: std::exception(e.c_str())
	{}
};

class vac_module_packet
{
public:
	vac_module_packet(unsigned char* data, unsigned long size)
		: m_module_data(nullptr)
		, m_module_size(0)
	{
		Narea::NBaseBinaryStream::Buffer packet_buffer(data, data + size);
		Narea::NBinaryStream binary_stream(&packet_buffer);

		binary_stream >> m_module_size;

		if (m_module_size > size - (sizeof(session_key_length) + session_key_length) || m_module_size <= 0 || m_module_size != size - sizeof(unsigned long) - (sizeof(session_key_length) + session_key_length))
			throw module_exception("m_module_size > size - (sizeof(session_key_length) + session_key_length) || m_module_size <= 0 || m_module_size != size - sizeof(unsigned long) - (sizeof(session_key_length) + session_key_length)");

		m_module_data = new unsigned char[m_module_size + 1];
		memset(m_module_data, 0, m_module_size + 1);

		binary_stream.rawRead(binary_stream.rpos(), m_module_size, m_module_data);

		//Decrypt module_data now
		xor_encrypt_decrypt("\xDE\xAD", 2, (char*)m_module_data, m_module_size);

		//Check if it is really a vac3 module and not a fake
		unsigned long unk_val;
		if (m_module_size < 0x200                      // MINIMUM MODULE SIZE SHOULD BE 512
			|| *(unsigned short*)m_module_data != 23117       // CHECK "MZ"
			|| (unk_val = *(unsigned long*)(m_module_data + 60), unk_val < 0x40)
			|| unk_val >= m_module_size - 248
			|| *(unsigned long*)(unk_val + m_module_data) != 17744)
		{
			throw module_exception("Not a valid VAC3 module, you should blacklist this IP! (1)");
		}
		else
		{
			if (*(unsigned long*)(m_module_data + 64) != 5655638)
				throw module_exception("Not a valid VAC3 module, you should blacklist this IP! (2)");
			if (*(unsigned long*)(m_module_data + 68) != 1)
				throw module_exception("Not a valid VAC3 module, you should blacklist this IP! (3)");
			if (m_module_size < *(unsigned long*)(m_module_data + 72))
				throw module_exception("Not a valid VAC3 module, you should blacklist this IP! (4)");
		}
	}

	~vac_module_packet()
	{
		if (m_module_data != nullptr)
			delete[] m_module_data;
		if (m_session_key)
			delete[] m_session_key;
	}

	unsigned long get_module_size()
	{
		return m_module_size;
	}

	unsigned char* get_module_data()
	{
		return m_module_data;
	}


private:

	unsigned long m_module_size;
	unsigned char* m_module_data;
};

class vac_request
{
public:
	vac_request(unsigned char* data, unsigned long size)
	{
		Narea::NBaseBinaryStream::Buffer packet_buffer(data, data + size);
		Narea::NBinaryStream binary_stream(&packet_buffer);

		binary_stream >> m_function_id;

		if (m_function_id < 0 || m_function_id > 4)
			throw std::exception("Invalid function id");

		binary_stream >> m_parameters_size;
		binary_stream >> m_result_size;

		m_vac_parameters = new unsigned char[m_parameters_size + 1];
		m_result = new unsigned char[0x1400];
		memset(m_vac_parameters, 0, m_parameters_size + 1);
		memset(m_result, 0, 0x1400);
		binary_stream.rawRead(binary_stream.rpos(), m_parameters_size, m_vac_parameters);
		binary_stream.rpos(binary_stream.rpos() + m_parameters_size);

		binary_stream >> m_parser_data_size;

		if (m_parser_data_size > 0x1400)
			throw std::exception(("Invalid ParserData size: " + std::to_string(m_parser_data_size)).c_str());

		m_parser_data = new unsigned char[0x1400];
		memset(m_parser_data, 0, 0x1400);
		binary_stream.rawRead(binary_stream.rpos(), m_parser_data_size, m_parser_data);
	}

	~vac_request()
	{
		if (m_vac_parameters)
			delete[] m_vac_parameters;

		if (m_result)
			delete[] m_result;

		if (m_parser_data)
			delete[] m_parser_data;
	}


	int get_function_id()
	{
		return m_function_id;
	}

	unsigned char* get_parameters()
	{
		return m_vac_parameters;
	}

	unsigned int get_parameters_size()
	{
		return m_parameters_size;
	}

	unsigned int* get_result_size_ptr()
	{
		return &m_result_size;
	}

	unsigned char* get_result()
	{
		return m_result;
	}

	unsigned char* get_parser_data()
	{
		return m_parser_data;
	}
	
	unsigned int get_parser_data_size()
	{
		return m_parser_data_size;
	}

private:
	int m_function_id;
	unsigned char* m_vac_parameters;
	unsigned int m_parameters_size;
	unsigned int m_result_size;
	unsigned char* m_result;

	unsigned int m_parser_data_size;
	unsigned char* m_parser_data;
};

class vac_response : public base_packet
{
public:
	vac_response(int function_id, int result_size, unsigned char* result)
	{
		Narea::NBaseBinaryStream::Buffer payload_buffer;
		m_buffer = new Narea::NBaseBinaryStream::Buffer();

		Narea::NBinaryStream binary_stream(&payload_buffer);
		Narea::NBinaryStream final_stream(m_buffer);

		binary_stream << function_id;
		binary_stream << result_size;

		binary_stream.rawWrite(binary_stream.wpos(), result_size, result);

		//Build header
		packet_header header;
		header.magic = 0x1337;
		header.id = vac_response_id;
		header.body_size = payload_buffer.size();

		final_stream << header;
		final_stream << payload_buffer;
	}
};


class vac_module_split
{
public:
	vac_module_split(unsigned char* data, unsigned long size)
		: m_split_data(nullptr)
		, m_split_size(0)
	{
		Narea::NBaseBinaryStream::Buffer packet_buffer(data, data + size);
		Narea::NBinaryStream binary_stream(&packet_buffer);

		binary_stream >> m_total_size;
		binary_stream >> m_split_size;

		/*if (m_split_size > size - (sizeof(session_key_length) + session_key_length) || m_split_size <= 0 || m_split_size != size - sizeof(unsigned long) - (sizeof(session_key_length) + session_key_length))
			throw module_exception("m_module_size > size - (sizeof(session_key_length) + session_key_length) || m_module_size <= 0 || m_module_size != size - sizeof(unsigned long) - (sizeof(session_key_length) + session_key_length)");
*/
		m_split_data = new unsigned char[m_split_size + 1];
		memset(m_split_data, 0, m_split_size + 1);

		binary_stream.rawRead(binary_stream.rpos(), m_split_size, m_split_data);
		binary_stream.rpos(binary_stream.rpos() + m_split_size);

		binary_stream >> m_ref_counter;

		////Check if it is really a vac3 module and not a fake
		//unsigned long unk_val;

		//if (m_module_size < 0x200                      // MINIMUM MODULE SIZE SHOULD BE 512
		//	|| *(unsigned short*)m_split_data != 23117       // CHECK "MZ"
		//	|| (unk_val = *(unsigned long*)(m_split_data + 60), unk_val < 0x40)
		//	|| unk_val >= m_split_size - 248
		//	|| *(unsigned long*)(unk_val + m_split_data) != 17744)
		//{
		//	throw module_exception("Not a valid VAC3 module, you should blacklist this IP! (1)");
		//}
		//else
		//{
		//	if (*(unsigned long*)(m_split_data + 64) != 5655638)
		//		throw module_exception("Not a valid VAC3 module, you should blacklist this IP! (2)");
		//	if (*(unsigned long*)(m_split_data + 68) != 1)
		//		throw module_exception("Not a valid VAC3 module, you should blacklist this IP! (3)");
		//	if (m_split_size < *(unsigned long*)(m_split_data + 72))
		//		throw module_exception("Not a valid VAC3 module, you should blacklist this IP! (4)");
		//}
	}

	~vac_module_split()
	{
		if (m_split_data != nullptr)
			delete[] m_split_data;
		if (m_session_key)
			delete[] m_session_key;
	}


	char* m_session_key;

	unsigned long m_total_size;

	unsigned long m_split_size;
	unsigned char* m_split_data;

	unsigned int m_ref_counter;
};

class vac_module_packet_tmp : public base_packet
{
public:
	vac_module_packet_tmp(unsigned char* module_data, unsigned long module_size)
	{
		Narea::NBaseBinaryStream::Buffer payload_buffer;
		m_buffer = new Narea::NBaseBinaryStream::Buffer();

		Narea::NBinaryStream binary_stream(&payload_buffer);
		Narea::NBinaryStream final_stream(m_buffer);

		binary_stream << module_size;
		binary_stream.rawWrite(binary_stream.wpos(), module_size, module_data);

		/*packet_header header;
		header.magic = 0x1337;
		header.id = vac_module_packet_id;
		header.body_size = payload_buffer.size();*/

		//final_stream << header;
		final_stream << payload_buffer;
	}
};

class vac_new_module : public base_packet
{
public:
	vac_new_module()
	{
		Narea::NBaseBinaryStream::Buffer payload_buffer;
		m_buffer = new Narea::NBaseBinaryStream::Buffer();

		Narea::NBinaryStream binary_stream(&payload_buffer);
		Narea::NBinaryStream final_stream(m_buffer);

		binary_stream << 0;

		//Build header
		packet_header header;
		header.magic = 0x1337;
		header.id = vac_new_module_id;
		header.body_size = payload_buffer.size();

		final_stream << header;
		final_stream << payload_buffer;
	}
};

class vac_file_error : public base_packet
{
public:
	vac_file_error()
	{
		Narea::NBaseBinaryStream::Buffer payload_buffer;
		m_buffer = new Narea::NBaseBinaryStream::Buffer();

		Narea::NBinaryStream binary_stream(&payload_buffer);
		Narea::NBinaryStream final_stream(m_buffer);

		binary_stream << 0;

		//Build header
		packet_header header;
		header.magic = 0x1337;
		header.id = vac_file_error_id;
		header.body_size = payload_buffer.size();

		final_stream << header;
		final_stream << payload_buffer;
	}
};