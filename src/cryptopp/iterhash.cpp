// iterhash.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

// prevent Sun's CC compiler from including this file automatically
#if !defined(__SUNPRO_CC) || defined(CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES)

#include "iterhash.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T, class BASE> void IteratedHashBase<T, BASE>::Update(const byte *input, size_t len)
{
	HashWordType oldCountLo = m_countLo, oldCountHi = m_countHi;
	if ((m_countLo = oldCountLo + HashWordType(len)) < oldCountLo)
		m_countHi++;             // carry from low to high
	m_countHi += (HashWordType)SafeRightShift<8*sizeof(HashWordType)>(len);
	if (m_countHi < oldCountHi || SafeRightShift<2*8*sizeof(HashWordType)>(len) != 0)
		throw HashInputTooLong(this->AlgorithmName());

	unsigned int blockSize = BlockSize();
	unsigned int num = ModPowerOf2(oldCountLo, blockSize);

	if (num != 0)	// process left over data
	{
		if ((num+len) >= blockSize)
		{
			memcpy((byte *)m_data.begin()+num, input, blockSize-num);
			HashBlock(m_data);
			input += (blockSize-num);
			len-=(blockSize - num);
			num=0;
			// drop through and do the rest
		}
		else
		{
			memcpy((byte *)m_data.begin()+num, input, len);
			return;
		}
	}

	// now process the input data in blocks of blockSize bytes and save the leftovers to m_data
	if (len >= blockSize)
	{
		if (input == (byte *)m_data.begin())
		{
			assert(len == blockSize);
			HashBlock(m_data);
			return;
		}
		else if (IsAligned<T>(input))
		{
			size_t leftOver = HashMultipleBlocks((T *)input, len);
			input += (len - leftOver);
			len = leftOver;
		}
		else
			do
			{   // copy input first if it's not aligned correctly
				memcpy(m_data, input, blockSize);
				HashBlock(m_data);
				input+=blockSize;
				len-=blockSize;
			} while (len >= blockSize);
	}

	memcpy(m_data, input, len);
}

template <class T, class BASE> byte * IteratedHashBase<T, BASE>::CreateUpdateSpace(size_t &size)
{
	unsigned int blockSize = BlockSize();
	unsigned int num = ModPowerOf2(m_countLo, blockSize);
	size = blockSize - num;
	return (byte *)m_data.begin() + num;
}

template <class T, class BASE> size_t IteratedHashBase<T, BASE>::HashMultipleBlocks(const T *input, size_t length)
{
	unsigned int blockSize = BlockSize();
	bool noReverse = NativeByteOrderIs(GetByteOrder());
	do
	{
		if (noReverse)
			HashEndianCorrectedBlock(input);
		else
		{
			ByteReverse(this->m_data.begin(), input, this->BlockSize());
			HashEndianCorrectedBlock(this->m_data);
		}

		input += blockSize/sizeof(T);
		length -= blockSize;
	}
	while (length >= blockSize);
	return length;
}

template <class T, class BASE> void IteratedHashBase<T, BASE>::PadLastBlock(unsigned int lastBlockSize, byte padFirst)
{
	unsigned int blockSize = BlockSize();
	unsigned int num = ModPowerOf2(m_countLo, blockSize);
	((byte *)m_data.begin())[num++]=padFirst;
	if (num <= lastBlockSize)
		memset((byte *)m_data.begin()+num, 0, lastBlockSize-num);
	else
	{
		memset((byte *)m_data.begin()+num, 0, blockSize-num);
		HashBlock(m_data);
		memset(m_data, 0, lastBlockSize);
	}
}

template <class T, class BASE> void IteratedHashBase<T, BASE>::Restart()
{
	m_countLo = m_countHi = 0;
	Init();
}

template <class T, class BASE> void IteratedHashBase<T, BASE>::TruncatedFinal(byte *digest, size_t size)
{
	this->ThrowIfInvalidTruncatedSize(size);

	PadLastBlock(this->BlockSize() - 2*sizeof(HashWordType));
	ByteOrder order = this->GetByteOrder();
	ConditionalByteReverse<HashWordType>(order, this->m_data, this->m_data, this->BlockSize() - 2*sizeof(HashWordType));

	this->m_data[this->m_data.size()-2] = order ? this->GetBitCountHi() : this->GetBitCountLo();
	this->m_data[this->m_data.size()-1] = order ? this->GetBitCountLo() : this->GetBitCountHi();

	HashEndianCorrectedBlock(this->m_data);
	ConditionalByteReverse<HashWordType>(order, this->m_digest, this->m_digest, this->DigestSize());
	memcpy(digest, this->m_digest, size);

	this->Restart();		// reinit for next use
}

NAMESPACE_END

#endif
