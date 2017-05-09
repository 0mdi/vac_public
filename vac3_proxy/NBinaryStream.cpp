

/******************************************************************************
Narea project - NextGen game hacking framework (c) mainframe.pw
-------------------------------------------------------------------------------
Original author:    Ende!
Modifications:
Contact:            ende@mainframe.pw
Last change:        07. April 2014
*******************************************************************************/

#include "NBinaryStream.hpp"

#include <sstream>
#include <iomanip>

namespace Narea
{

	// ====================================================================== //
	// [NIBinaryStream]                                                       //
	// ====================================================================== //

	std::string NIBinaryStream::extractString8(streamoffs pos, size_t maxLen) const
	{
		streamoffs curPos = pos;
		while (*constPtr<char>(curPos) != 0 && (maxLen == 0 || curPos - pos < maxLen))
			++curPos;
		return std::string(constPtr<char>(pos), curPos - pos);
	} // ==> extractString8

	// ---------------------------------------------------------------------- //

	std::wstring NIBinaryStream::extractString16(streamoffs pos, size_t maxLen) const
	{
		streamoffs curPos = pos;
		while (*constPtr<wchar_t>(curPos) != 0
			&& (maxLen == 0 || curPos - pos < maxLen * sizeof(wchar_t)))
			++curPos;
		return std::wstring(constPtr<wchar_t>(pos), curPos - pos);
	} // ==> extractString16

	// ---------------------------------------------------------------------- //

	std::string NIBinaryStream::hexDump(streamoffs pos, size_t len) const
	{
		_validateOffset(pos, len);

		std::stringstream ss;
		ss << std::hex << std::setfill('0');

		// Loop through buffer's bytes
		for (uint i = pos, j = 0; i < len + pos; ++i, ++j)
		{
			// First byte in line? Prefix with position
			if (j == 0)
				ss << "0x" << std::setw(4) << (i - pos);

			// Print byte
			ss << ' ' << std::setw(2) << (int)m_pBuffer->data()[i];

			// Last byte in row or last byte? Append ASCII dump
			bool bLastRound = (i == len + pos - 1);
			if (j == 15 || bLastRound)
			{
				// If last round, fill delta with spaces
				if (bLastRound)
					for (int k = 16 - j; k != 1; --k)
						ss << "   ";

				ss << ' ';

				// Create ASCII dump
				for (uint k = 0
					; (bLastRound && k <= j) || (!bLastRound && k < 16)
					; ++k)
				{
					unsigned char chCur = m_pBuffer->data()[i - j + k];
					ss << (::isprint(chCur) ? (char)chCur : '.');
				}
				ss << std::endl;
				j = -1;
			}
		}

		return ss.str();
	} // ==> hexDump

	// ====================================================================== //

}

