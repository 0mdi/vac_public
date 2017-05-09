#include "VACStringArray.hpp"

#include <algorithm>
#include <cassert>

VACStringArray::VACStringArray(char *begin) noexcept
{
	AnalyzeStrings(begin);
}

void VACStringArray::AnalyzeStrings(char *begin)
{
	if (m_strings.size())
		m_strings.clear();

	while (true)
	{
		char* str = begin;
		auto len = strlen(str);

		if (!len)
			break;

		begin += len + 1;

		m_strings.push_back(str);
	}
}

unsigned int VACStringArray::GetSize() const
{
	return m_strings.size();
}

char* VACStringArray::Get(int index)
{
	return m_strings.at(index);
}

void VACStringArray::Remove(int index)
{
	if (GetSize() <= 0)
		return;

	auto begin = Get(0);
	auto end = Get(GetSize() - 1);

	//Last element to remove? Fix m_end
	if (index == GetSize() - 1)
	{
		memset(Get(index), 0, strlen(Get(index)));
		m_strings.erase(m_strings.end() - 1);
		AnalyzeStrings(begin);
		return;
	}

	//Overwrite that shit now
	auto size = (end + strlen(end) + 1) - Get(index + 1);
	char *tmpCopy = new char[size];
	std::copy(Get(index + 1), end + strlen(end) + 1, tmpCopy);

	memset(Get(index), 0x00, (end + strlen(end) + 1) - Get(index));
	std::copy(tmpCopy, tmpCopy + size, Get(index));

	m_strings.erase(m_strings.end() - 1);

	delete[] tmpCopy;

	AnalyzeStrings(begin);
}