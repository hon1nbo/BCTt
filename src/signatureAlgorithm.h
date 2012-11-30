/*******************************************************************************
* File: signatureAlgorithm.h
* 
* This provides the interface for algorithm objects.
* These objects are used by signatureConfig.h
* This is a generic wrapper for other algorithms provided by the crypto library,
* ensuring that there is a common interface.
* 
* Author: James (Jimmy) Hartnett
*******************************************************************************/

#ifndef signatureAlgorithm_h
#define signatureAlgorithm_h

#include <string>
#include "supportedAlgorithms.h"

using namespace std;

class signatureAlgorithm
{
	public:
            signatureAlgorithm();
            signatureAlgorithm(string);
            ~signatureAlgorithm();
            void setAlgorithm(string);
            void setOutputEncoding(string);
            string getAlgorithm();
            string getDigest();
            byte* getDigestBytes();
            void createDigest(string);
	private:
            
            template<class Digest>
                void doDigest(string input)
                {
                    _digestSize = (Digest::DIGESTSIZE);
                    _digest = new byte[ _digestSize ];
                    Digest().CalculateDigest( _digest, (byte*) input.c_str(), input.length() );
                }
            
            string getDigestHex();
            string getDigestBase64();
            string base64_encode(unsigned char const*, unsigned int);

            string _algorithm;
            string _outputEncoding;
            byte* _digest;
            size_t _digestSize;
            bool _ready;
};

#endif