/*******************************************************************************
* File: signatureAlgorithm.cpp
* 
* This provides the implementation for algorithm objects.
* These objects are used by signatureConfig
* This is a generic wrapper for other algorithms provided by the crypto library,
* ensuring that there is a common interface.
* 
* Author: James (Jimmy) Hartnett
*******************************************************************************/

#include "signatureAlgorithm.h"
#include "cryptopp/md2.h"
#include <string.h>

using namespace std;

signatureAlgorithm::signatureAlgorithm()
{
    signatureAlgorithm("");
}

signatureAlgorithm::signatureAlgorithm(string algorithmName)
{
    _digestSize = (size_t) 0;
    _keySize = (size_t) 0;
    _ready = false;
    _outputEncoding = "none";
    _alternateEncoder = false;
    setAlgorithm(algorithmName);
}

signatureAlgorithm::~signatureAlgorithm()
{
    if (((int) _keySize) == 0)
        delete [] _digest;
}

/******************************************************
 * setAlgorithm(string) sets the algorithm to use, and
 * parses out the encoding information if it exists
 * 
 * acceptable formats:
 * 
 * algorithm
 * algorithm:encoding
 ******************************************************/

void signatureAlgorithm::setAlgorithm(string algorithm)
{
    size_t found;
    found = algorithm.find(":");
    if (found < algorithm.length())
    {
        _outputEncoding = algorithm.substr( (found + 1) );
        _algorithm = algorithm.substr(0, found);
    }
    else
        _algorithm = algorithm;
}

/**********************************************************************
 * setOutputEncoding allows the encoding of the algorithm output to be
 * manually changed
 *********************************************************************/

void signatureAlgorithm::setOutputEncoding(string encoding)
{
    _outputEncoding = encoding;
}

/***************************************************************
 * getAlgorithm returns the string name of the algorithm in use
 **************************************************************/

string signatureAlgorithm::getAlgorithm()
{
    return _algorithm;
}

/***********************************************************************
 * getDigest() returns the digest as a string in the requested encoding
 **********************************************************************/

string signatureAlgorithm::getDigest()
{
    if (_ready)
    {
        if (_outputEncoding == "none")
            return string(reinterpret_cast<const char*>(_digest));
        else if ((_outputEncoding == "hex") & (_alternateEncoder == false))
            return getDigestHex();
        else if ((_outputEncoding == "hex") & (_alternateEncoder == true))
            return getAlternateDigestHex();
        else if (_outputEncoding == "base64")
            return getDigestBase64();
        else
            return "ERROR";
    }
    else
        return "NOT READY";
}

/*************************************************************************
 * runs the digest creation routine. Sets the "_ready" flag if successful.
 *************************************************************************/

void signatureAlgorithm::createDigest(string input)
{
    bool digestFail = false;
    size_t found = 0;
    
    if (_algorithm == "md5")
    {
        doHashDigest<CryptoPP::MD5>(input);
    }
    else if (_algorithm == "md2")
    {
        doHashDigest<CryptoPP::MD2>(input);
    }
    else if (_algorithm == "md4")
    {
        doHashDigest<CryptoPP::MD4>(input);
    }
    else if (_algorithm == "sha1")
    {
        doHashDigest<CryptoPP::SHA1>(input);
    }
    else if (_algorithm == "sha256")
    {
        doHashDigest<CryptoPP::SHA256>(input);
    }
    else if (_algorithm == "sha512")
    {
        doHashDigest<CryptoPP::SHA512>(input);
    }
    else if (_algorithm == "sha384")
    {
        doHashDigest<CryptoPP::SHA384>(input);
    }
    else if (_algorithm.find("hmac<md5>") < _algorithm.length())
    {
        doHmacDigest<CryptoPP::HMAC<CryptoPP::MD5> >(input);
    }
    else if (_algorithm.find("hmac<md2>") < _algorithm.length())
    {
        doHmacDigest<CryptoPP::HMAC<CryptoPP::MD2> >(input);
    }
    else if (_algorithm.find("hmac<md4>") < _algorithm.length())
    {
        doHmacDigest<CryptoPP::HMAC<CryptoPP::MD4> >(input);
    }
    else if (_algorithm.find("hmac<sha1>") < _algorithm.length())
    {
        doHmacDigest<CryptoPP::HMAC<CryptoPP::SHA1> >(input);
    }
    else if (_algorithm.find("hmac<sha256>") < _algorithm.length())
    {
        doHmacDigest<CryptoPP::HMAC<CryptoPP::SHA256> >(input);
    }
    else if (_algorithm.find("hmac<sha384>") < _algorithm.length())
    {
        doHmacDigest<CryptoPP::HMAC<CryptoPP::SHA384> >(input);
    }
    else if (_algorithm.find("hmac<sha512>") < _algorithm.length())
    {
        doHmacDigest<CryptoPP::HMAC<CryptoPP::SHA512> >(input);
    }
    else
        digestFail = true;
    
    if (!digestFail)
        _ready = true;
    else
        _ready = false;
}

/*****************************************************************************
 * getDigestHex returns the _digest of the algorithm as a hex-encoded string
 *****************************************************************************/

string signatureAlgorithm::getDigestHex()
{
    string output;
    
    CryptoPP::HexEncoder encoder;
    
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( _digest, _digestSize );
    encoder.MessageEnd();
    
    cout << "Hex Digest: " << output << endl;
    
    return output;
}

string signatureAlgorithm::getAlternateDigestHex()
{
    string output;
    string tempDigest = string(reinterpret_cast<const char*>(_digest));
    
    CryptoPP::StringSource(tempDigest, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(output)
		) // HexEncoder
	); // StringSource
    
    cout << "Hex Digest: " << output << endl;
    
    return output;
}

/**************************************************************************
 * getDigestBase64 returns the _digest of the algorithm as a base64 string
 **************************************************************************/

string signatureAlgorithm::getDigestBase64()
{
    return base64_encode(_digest, _digestSize); // currently using a custom base 64 for documentation issues with crypto++
}


/*******************************************************************************
 * getDigestBytes returns a pointer to the raw bytes should the calling program
 * use them
 * typedef const unsigned char* bytes
 ******************************************************************************/

byte* signatureAlgorithm::getDigestBytes()
{
    if (_ready)
        return _digest;
    else
    {
        string tmpstr = "0";
        return (byte*) tmpstr.c_str();//reinterpret_cast<const unsigned char*>
    }
}


/*****************************************************************
* Just a base64 encoder. I had some trouble with the CryptoPP one.
* Will make the switch back eventually
******************************************************************/

string signatureAlgorithm::base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {

	static const string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

  string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}