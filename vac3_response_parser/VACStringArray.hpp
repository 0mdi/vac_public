#pragma once

#include <vector>

class VACStringArray
{
public:
	VACStringArray(char *begin) noexcept;

	VACStringArray(const VACStringArray&) = default;               // Copy constructor
	VACStringArray(VACStringArray&&) = default;                    // Move constructor
	VACStringArray& operator=(const VACStringArray&) & = default;  // Copy assignment operator
	VACStringArray& operator=(VACStringArray&&) & = default;       // Move assignment operator
	virtual ~VACStringArray() { }                     // Destructor

	unsigned int GetSize() const;

	char* Get(int index);
	void Remove(int index);

private:
	void AnalyzeStrings(char* begin);

private:
	std::vector<char*> m_strings;
};