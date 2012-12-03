#ifndef supportedAlgorithms_h
#define supportedAlgorithms_h

#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/filters.h"

/******************
* Hash Functions
******************/

#include "cryptopp/md2.h"
#include "cryptopp/md4.h"
#include "cryptopp/md5.h"
#include "cryptopp/sha.h"	// sha1, sha256, sha384, sha512

/*******************************
 * Message Authentication Codes
 ******************************/

#include "cryptopp/hmac.h"      // md2, md4, md5, sha1, sha256, sha384, sha512

/******************
* Encoding Options
******************/

#include "cryptopp/hex.h"
// base64 via direct implementation rather than Crypto++
// none

#endif