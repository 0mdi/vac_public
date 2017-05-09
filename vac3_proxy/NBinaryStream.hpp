/******************************************************************************
Narea project - NextGen game hacking framework (c) mainframe.pw
-------------------------------------------------------------------------------
Original author:    Ende!
Modifications:
Contact:            ende@mainframe.pw
Last change:        07. April 2014
*******************************************************************************/

/**
* @file This file contains the \c NBinaryBuffer classes.
*/

#ifndef NBINARYSTREAM_H
#define NBINARYSTREAM_H

#include <type_traits>
#include <vector>
#include <stdint.h>

#include <assert.h>

typedef uint32_t uint;
typedef uint8_t byte;

namespace Narea
{

	// ====================================================================== //
	// [NBaseBinaryStream]                                                    //
	// ====================================================================== //

	/**
	* @brief   Base class for binary streams.
	* @see     NIBinaryStream
	* @see     NOBinaryStream
	* @see     NBinarySteam
	*/
	class NBaseBinaryStream
	{

	public:

		typedef std::vector<byte> Buffer;
		typedef Buffer::size_type streamsize;
		typedef streamsize streamoffs;

	protected:

		Buffer *m_pBuffer;

	public:

		/**
		* @brief   Constructor.
		* @param   pBuffer The buffer to work on.
		*/
		NBaseBinaryStream(Buffer *pBuffer);

		/**
		* @brief   Destructor.
		*/
		virtual ~NBaseBinaryStream() {}

	}; // ==> NBaseBinaryStream

	// ====================================================================== //
	// [NIBinaryStream]                                                       //
	// ====================================================================== //

	/**
	* @brief   Input stream for parsing binary data.
	*
	* Reading data accesses perform boundary checks. All methods are guaranteed
	* to throw a @c NXOutOfBounds in case a requested read operation exceeds
	* the managed buffer's boundaries.
	*/
	class NIBinaryStream : public virtual NBaseBinaryStream
	{

	protected:

		streamoffs m_rpos;

		/**
		* @internal
		* @brief   Validates if the given offset and length lie outside the
		*          buffers boundaries.
		* @param   offs    The offset to check
		* @param   len     The length to add.
		*/
		void _validateOffset(streamoffs offs, streamsize len) const;

	public:

		/**
		* @copydoc NBaseBinaryStream::NBaseBinaryStream
		*/
		NIBinaryStream(Buffer *pBuffer);

		/**
		* @brief   Destructor.
		*/
		virtual ~NIBinaryStream() {}

		/**
		* @brief   Gets the read offset.
		* @return  The read offset.
		*/
		streamoffs rpos() const;

		/**
		* @brief   Sets the read offset.
		* @param   pos The read offset.
		* @return  This instance.
		*/
		NIBinaryStream& rpos(streamoffs pos);

		/**
		* @brief   Extracts a potion of the buffer into a new buffer.
		* @param   pos The position to start extracting.
		* @param   len The length of the data to extract.
		* @return  A new buffer containing the requested buffer region.
		*/
		Buffer sub(streamoffs pos, streamsize len) const;

		/**
		* @brief   Extracts an ANSI string from the buffer.
		* @param   pos             The position to start reading the string.
		* @param   maxLen          The maximum length of the string.
		*                          0 for infinite.
		*/
		std::string extractString8(streamoffs pos = 0, streamsize maxLen = 0) const;

		/**
		* @brief   Extracts a wide string from the buffer.
		* @param   pos             The position to start reading the string
		* @param   maxLen          The maximum length of the string
		*                          (in characters). 0 for infinite.
		*/
		std::wstring extractString16(streamoffs pos = 0, streamsize maxLen = 0) const;

		/**
		* @brief   Generates a hex dump using the buffer's data.
		*
		* @param   pos   The position.
		* @param   len   The length.
		* @return  The hex dump.
		*
		* Example return (200 bytes):
		* @code
		*   0x0000 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f ................
		*   0x0010 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f ................
		*   0x0020 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f  !"#$%&'()*+,-./
		*   0x0030 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 0123456789:;<=>?
		*   0x0040 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f @ABCDEFGHIJKLMNO
		*   0x0050 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f PQRSTUVWXYZ[\]^_
		*   0x0060 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f `abcdefghijklmno
		*   0x0070 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f pqrstuvwxyz{|}~.
		*   0x0080 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f ................
		*   0x0090 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f ................
		*   0x00a0 a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af ................
		*   0x00b0 b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf ................
		*   0x00c0 c0 c1 c2 c3 c4 c5 c6 c7                         ........
		* @endcode
		*/
		std::string hexDump(streamoffs pos, streamsize len) const;

		/**
		* @overload
		* The hex-dump contains the whole buffer from 0 to buffer's size.
		*/
		std::string hexDump() const;

		/**
		* @brief   Retrieves a constant pointer of a location inside the
		*          buffer.
		* @tparam  T       The pointer's type.
		* @param   pos     The position.
		* @return  The desired pointer.
		*/
		template<typename T> const T* constPtr(streamoffs pos = 0) const;

		/**
		* @brief   Stream extraction operator.
		* @tparam  T       The type of data to extract.
		* @param   rData   The reference to extract into.
		* @return  This instance.
		*/
		template<typename T> NIBinaryStream& operator >> (T &rData);

		/// @overload
		template<typename T> const NIBinaryStream& operator >> (T &rData) const;

		/**
		* @brief   Reads data from the stream rawly.
		* @param   pos     The position to read from.
		* @param   len     The length.
		* @param   pBuf    The buffer to read into.
		*/
		void rawRead(streamoffs pos, streamsize len, byte *pBuf) const;

		/// @overload
		template<typename T> T rawRead(streamoffs pos) const;

	}; // ==> NIBinaryStream

	// ====================================================================== //
	// [NOBinaryStream]                                                       //
	// ====================================================================== //

	/**
	* @brief   Output stream for binary data.
	*
	* In case a write operation would exceed the buffer's size, the size is
	* automatically advanced to fit the new requirements. If an operation
	* would grow the buffer beyond it's @c max_size, a @c NXOutOfBounds
	* exception will be raised.
	*/
	class NOBinaryStream : public virtual NBaseBinaryStream
	{

	protected:

		streamoffs  m_wpos;
		streamsize  m_blockSize;

		/**
		* @internal
		* @brief   Grows the buffer if the given pos + len does not fit into
		*          the buffer anymore.
		* @param   pos The position.
		* @param   len The length.
		*/
		void _growIfRequired(streamoffs pos, streamsize len) const;

	public:

		/**
		* @copydoc NBaseBinaryStream::NBaseBinaryStream
		* @param   blockSize   Sets the block size for reallocation operations.
		*/
		NOBinaryStream(Buffer *pBuffer, streamsize blockSize = 256);

		/**
		* @brief   Destructor.
		*/
		virtual ~NOBinaryStream() {}

		/**
		* @brief   Addition assignment operator.
		* @param   appendFrom  The buffer to append.
		* @return  This instance.
		* The given buffer is appended to the end of the managed buffer,
		* not at the current write offset.
		*/
		NOBinaryStream& operator += (const Buffer &appendFrom);

		/**
		* @brief   Gets the write offset.
		* @return  The current write offset.
		*/
		streamoffs wpos() const;

		/**
		* @brief   Sets the write offset.
		* @param   pos The write offset.
		* @return  This instance.
		*/
		NOBinaryStream& wpos(streamoffs pos);

		/**
		* @brief   Aligns the write offset to a given value.
		* @param   alignment   The alignment.
		* @return  This instance.
		*/
		NOBinaryStream& alignWpos(streamsize alignment);

		/**
		* @brief   Appends a buffer to the managed buffer.
		* @copydetails operator+=
		*/
		NOBinaryStream& append(const Buffer &appendFrom);

		/**
		* @brief   Clears the managed buffer.
		* @return  This instance.
		*/
		NOBinaryStream& clear();

		/**
		* @brief   Clears a fragment of the managed buffer.
		* @param   pos The position to start clearing.
		* @param   len The length of the fragment to clear.
		* @return  This instance.
		*/
		NOBinaryStream& clear(streamoffs pos, streamsize len);

		/**
		* @brief   Fills the managed buffer with the given value.
		* @param   value   The value.
		* @return  This instance.
		*/
		NOBinaryStream& fill(uint8_t value);

		/**
		* @brief   Fills a fragment of the managed buffer with the given value.
		* @param   pos     The position to start filling.
		* @param   len     The length of the fragment to fill.
		* @param   value   The value.
		* @return  This instance.
		*/
		NOBinaryStream& fill(streamoffs pos, streamsize len, uint8_t value);

		/**
		* @brief   Retrieves a writable pointer to
		* @tparam  T   The pointer type to retrieve.
		* @param   pos The position.
		* @return  The desired pointer.
		*/
		template<typename T> T* ptr(streamoffs pos = 0);

		/**
		* @brief   Stream insertion operator.
		* @param   rData   The data to append at @c wpos.
		* @return  This instance.
		*/
		template<typename T> NOBinaryStream& operator << (const T &rData);

		/**
		* @brief   Stream insertion operator.
		* @param   buffer  The buffer to append at @c wpos.
		* @return  This instance.
		*/
		NOBinaryStream& operator << (const Buffer &buffer);

		/**
		* @brief   Writes memory into the managed buffer rawly.
		* @param   pos     The position to write to.
		* @param   len     The length.
		* @param   pSrc    The source of data.
		*/
		void rawWrite(streamoffs pos, streamsize len, const byte *pSrc);

		/// @overload
		template<typename T> void rawWrite(streamoffs pos, const T &data);

	}; // ==> NOBinaryStream

	// ====================================================================== //
	// [NBinaryStream]                                                        //
	// ====================================================================== //

	/**
	* @brief Combined input and output stream for binary data.
	* @copydetails Narea::NIBinaryStream
	* @copydetails Narea::NOBinaryStream
	*/
	class NBinaryStream : public NIBinaryStream, public NOBinaryStream
	{
	public:
		/// @copydoc NOBinaryStream::NOBinaryStream
		NBinaryStream(Buffer *pBuffer, streamsize blockSize = 256)
			: NIBinaryStream(pBuffer)
			, NOBinaryStream(pBuffer)
			, NBaseBinaryStream(pBuffer)
		{}
	}; // ==> NBinaryStream

	// ====================================================================== //
	// Implementation of inline and template functions                        //
	// [NBaseBinaryStream]                                                    //
	// ====================================================================== //

	inline NBaseBinaryStream::NBaseBinaryStream(Buffer *pBuffer)
		: m_pBuffer(pBuffer)
	{
		assert(pBuffer);
	} // ==> ctor

	// ====================================================================== //
	// Implementation of inline and template functions [NIBinaryStream]       //
	// ====================================================================== //

	inline NIBinaryStream::NIBinaryStream(Buffer *pBuffer)
		: NBaseBinaryStream(pBuffer)
		, m_rpos(0)
	{} // ==> ctor

	// ---------------------------------------------------------------------- //

	inline void NIBinaryStream::_validateOffset(streamoffs offs, streamsize len) const
	{
		if (offs + len > m_pBuffer->size())
			throw "the requested offset is out of bounds";
	} // ==> _validateOffset

	// ---------------------------------------------------------------------- //

	inline auto NIBinaryStream::rpos() const -> streamoffs
	{
		return m_rpos;
	} // ==> rpos() const

	// ---------------------------------------------------------------------- //

	inline NIBinaryStream& NIBinaryStream::rpos(streamoffs pos)
	{
		// TODO: validate rpos here?
		m_rpos = pos;
		return *this;
	} // ==> rpos(streamoffs)

	// ---------------------------------------------------------------------- //

	inline auto NIBinaryStream::sub(streamoffs pos, streamsize len) const -> Buffer
	{
		_validateOffset(pos, len);
		return std::move(Buffer(m_pBuffer->begin() + pos, m_pBuffer->begin() + pos + len));
	} // ==> sub

	// ---------------------------------------------------------------------- //

	template<typename T> inline
		const T* NIBinaryStream::constPtr(streamoffs pos) const
	{
		_validateOffset(pos, sizeof(T));
		return reinterpret_cast<T*>(m_pBuffer->data() + pos);
	} // ==> constPtr

	// ---------------------------------------------------------------------- //

	template<typename T> inline
		NIBinaryStream& NIBinaryStream::operator >> (T &rData)
	{
		rData = *constPtr<T>(m_rpos);
		m_rpos += sizeof(T);
		return *this;
	} // ==> operator >> (T&)

	// ---------------------------------------------------------------------- //

	template<typename T> inline
		const NIBinaryStream& NIBinaryStream::operator >> (T &rData) const
	{
		rData = *constPtr<T>(m_rpos);
		m_rpos += sizeof(T);
		return *this;
	} // ==> operator >> (T&) const

	// ---------------------------------------------------------------------- //

	inline void NIBinaryStream::rawRead(streamoffs pos, streamsize len, byte *pBuf) const
	{
		_validateOffset(pos, len);
		std::copy(m_pBuffer->begin() + pos, m_pBuffer->begin() + pos + len, pBuf);

	} // ==> rawRead

	// ---------------------------------------------------------------------- //

	template<typename T> inline
		T NIBinaryStream::rawRead(streamoffs pos) const
	{
		return *constPtr<T>(pos);
	} // ==> rawRead

	// ---------------------------------------------------------------------- //

	inline std::string NIBinaryStream::hexDump() const
	{
		return std::move(hexDump(0, m_pBuffer->size()));
	} // ==> hexDump

	// ====================================================================== //
	// Implementation of inline and template functions [NOBinaryStream]       //
	// ====================================================================== //

	inline NOBinaryStream::NOBinaryStream(Buffer *pBuffer, streamsize blockSize)
		: NBaseBinaryStream(pBuffer)
		, m_blockSize(blockSize)
		, m_wpos(0)
	{} // ==> ctor

	// ---------------------------------------------------------------------- //

	inline void NOBinaryStream::_growIfRequired(streamoffs pos, streamsize len) const
	{
		streamoffs end = pos + len;

		// Does it fit without any alteration? Fine.
		if (end <= m_pBuffer->size())
			return;

		// Does it fit into the capacity?
		if (end <= m_pBuffer->capacity())
		{
			m_pBuffer->resize(end);
			return;
		}

		// Nope, realloc. Does requested position exceed maximum allowed size?
		if (end > m_pBuffer->max_size())
			throw "tried to grow buffer beyond max_size";

		// Grow buffer.
		m_pBuffer->reserve(((end + m_blockSize - 1) / m_blockSize) * m_blockSize);
		m_pBuffer->resize(end);
	} // ==> _growIfRequired

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::operator += (const Buffer &rAppendFrom)
	{
		append(rAppendFrom);
		return *this;
	} // ==> operator += (const Buffer&)

	// ---------------------------------------------------------------------- //

	inline auto NOBinaryStream::wpos() const -> streamoffs
	{
		return m_wpos;
	} // ==> wpos() const

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::wpos(streamoffs pos)
	{
		m_wpos = pos;
		return *this;
	} // ==> wpos(streamoffs)

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::alignWpos(streamsize alignment)
	{
		m_wpos = (m_wpos + alignment - 1) * alignment;
		return *this;
	} // ==> alignWpos

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::append(const Buffer &appendFrom)
	{
		_growIfRequired(m_wpos, appendFrom.size());
		std::copy(appendFrom.begin(), appendFrom.end(),
			m_pBuffer->begin() + m_pBuffer->size());
		return *this;
	} // ==> append

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::clear(streamoffs pos, streamsize len)
	{
		fill(pos, len, 0);
		return *this;
	} // ==> clear(streamoffs, streamsize)

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::clear()
	{
		return clear(0, m_pBuffer->size());
	} // ==> clear()

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::fill(streamoffs pos, streamsize len, uint8_t value)
	{
		_growIfRequired(pos, len);
		std::fill(m_pBuffer->begin() + pos, m_pBuffer->begin() + pos + len, value);
		return *this;
	} // ==> fill(streamoffs, streamsize, uint8_t)

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::fill(uint8_t value)
	{
		return fill(0, m_pBuffer->size(), value);
	} // ==> fill(uint8_t)

	// ---------------------------------------------------------------------- //

	template<typename T> inline
		T* NOBinaryStream::ptr(streamoffs pos)
	{
		_growIfRequired(pos, sizeof(T));
		return reinterpret_cast<T*>(m_pBuffer->data() + pos);
	} // ==> ptr

	// ---------------------------------------------------------------------- //

	template<typename T> inline
		NOBinaryStream& NOBinaryStream::operator << (const T &data)
	{
		rawWrite(m_wpos, data);
		//m_wpos += sizeof(T);
		return *this;
	} // ==> operator << (cosnt T&)

	// ---------------------------------------------------------------------- //

	inline NOBinaryStream& NOBinaryStream::operator << (const Buffer &buffer)
	{
		_growIfRequired(m_wpos, buffer.size());
		std::copy(buffer.cbegin(), buffer.cend(), m_pBuffer->begin() + m_wpos);
		m_wpos += buffer.size();
		return *this;
	} // ==> operator << (const Buffer&)

	// ---------------------------------------------------------------------- //

	inline void NOBinaryStream::rawWrite(streamoffs pos, streamsize len, const byte *pSrc)
	{
		_growIfRequired(pos, len);
		std::copy(pSrc, pSrc + len, m_pBuffer->begin() + pos);
		m_wpos += len;
	} // ==> rawWrite(streamoffs, streamsize, const byte*)

	// ---------------------------------------------------------------------- //

	template<typename T> inline
		void NOBinaryStream::rawWrite(streamoffs pos, const T &data)
	{
		*ptr<T>(pos) = data;
		m_wpos += sizeof(T);
	} // ==> rawWrite(streamoffs, T)

	// ====================================================================== //

} // ==> Narea

#endif // ==> NBINARYSTREAM_H