#pragma once
#include "NBinaryStream.hpp"

#include <string>

enum packet_id : unsigned char
{
	vac_module_packet_id,
	vac_request_id,
	vac_response_id,
	vac_module_split_id,
	vac_new_module_id,
	vac_file_error_id
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

class vac_module_packet : public base_packet
{
public:
	vac_module_packet(unsigned char* module_data, unsigned long module_size)
	{
		Narea::NBaseBinaryStream::Buffer payload_buffer;
		m_buffer = new Narea::NBaseBinaryStream::Buffer();

		Narea::NBinaryStream binary_stream(&payload_buffer);
		Narea::NBinaryStream final_stream(m_buffer);

		binary_stream << module_size;
		binary_stream.rawWrite(binary_stream.wpos(), module_size, module_data);

		packet_header header;
		header.magic = 0x1337;
		header.id = vac_module_packet_id;
		header.body_size = payload_buffer.size();

		final_stream << header;
		final_stream << payload_buffer;
	}
};

class vac_request : public base_packet
{
public:
	vac_request(int function_id, int parameters_size, int result_size, unsigned char* vac_parameters, std::vector<unsigned char> parser_data)
	{
		Narea::NBaseBinaryStream::Buffer payload_buffer;
		m_buffer = new Narea::NBaseBinaryStream::Buffer();

		Narea::NBinaryStream binary_stream(&payload_buffer);
		Narea::NBinaryStream final_stream(m_buffer);

		binary_stream << function_id;
		binary_stream << parameters_size;
		binary_stream << result_size;

		binary_stream.rawWrite(binary_stream.wpos(), parameters_size, vac_parameters);

		binary_stream << (unsigned int)parser_data.size();
		binary_stream << parser_data;

		//Build header
		packet_header header;
		header.magic = 0x1337;
		header.id = vac_request_id;
		header.body_size = payload_buffer.size();

		final_stream << header;
		final_stream << payload_buffer;
	}
};

class vac_response
{
public:
	vac_response(unsigned char* data, unsigned long size)
	{
		Narea::NBaseBinaryStream::Buffer packet_buffer(data, data + size);
		Narea::NBinaryStream binary_stream(&packet_buffer);

		binary_stream >> m_function_id;
		binary_stream >> m_result_size;

		m_result = new unsigned char[m_result_size + 1];
		memset(m_result, 0x00, m_result_size + 1);
		binary_stream.rawRead(binary_stream.rpos(), m_result_size, m_result);
	}

	~vac_response()
	{
		if (m_result)
			delete[] m_result;
	}

	int get_function_id()
	{
		return m_function_id;
	}

	int get_result_size()
	{
		return m_result_size;
	}

	unsigned char* get_result()
	{
		return m_result;
	}

private:
	int m_function_id;
	int m_result_size;
	unsigned char* m_result;
};

class vac_module_split : public base_packet
{
public:
	vac_module_split(unsigned long total_size, unsigned char* split_data, unsigned long split_size,  unsigned int ref_counter)
	{
		Narea::NBaseBinaryStream::Buffer payload_buffer;
		m_buffer = new Narea::NBaseBinaryStream::Buffer();

		Narea::NBinaryStream binary_stream(&payload_buffer);
		Narea::NBinaryStream final_stream(m_buffer);

		binary_stream << total_size;

		binary_stream << split_size;
		binary_stream.rawWrite(binary_stream.wpos(), split_size, split_data);

		binary_stream << ref_counter;

		packet_header header;
		header.magic = 0x1337;
		header.id = vac_module_split_id;
		header.body_size = payload_buffer.size();

		final_stream << header;
		final_stream << payload_buffer;
	}
};

class vac_new_module
{
public:
	vac_new_module(unsigned char* data, unsigned long size)
	{
		Narea::NBaseBinaryStream::Buffer packet_buffer(data, data + size);
		Narea::NBinaryStream binary_stream(&packet_buffer);
	}

};
