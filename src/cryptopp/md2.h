#ifndef CRYPTOPP_MD2_H
#define CRYPTOPP_MD2_H

#include "cryptlib.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

/// <a href="http://www.weidai.com/scan-mirror/md.html#MD2">MD2</a>
/** 128 Bit Hash */
class MD2 : public HashTransformation
{
public:
	MD2();
	void Update(const byte *input, size_t length);
	void TruncatedFinal(byte *hash, size_t size);
	unsigned int DigestSize() const {return DIGESTSIZE;}
	static const char * StaticAlgorithmName() {return "MD2";}

	CRYPTOPP_CONSTANT(DIGESTSIZE = 16)
	CRYPTOPP_CONSTANT(BLOCKSIZE = 16)

private:
	void Transform();
	void Init();
	SecByteBlock m_X, m_C, m_buf;
	unsigned int m_count;
};

NAMESPACE_END

#endif
