/*******************************************************************************
* File: signatureAlgorithm.h
* 
* This provides the interface for algorithm objects.
* These objects are used by signatureConfig.h
* This is a generic wrapper for other algorithms provided by the crypto library,
* ensuring that there is a common interface.
* 
* Author: Hon1nbo
*******************************************************************************/

#ifndef signatureAlgorithm_h
#define signatureAlgorithm_h

#include <string>
#include <iostream>
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
                void doHashDigest(string input)
                {
                    _digestSize = (Digest::DIGESTSIZE);
                    cout << "_digestSize: " << _digestSize << endl;
                    _digest = new byte[ _digestSize ];
                    Digest().CalculateDigest( _digest, (byte*) input.c_str(), input.length() );
                    cout << "_digest: " << string(reinterpret_cast<const char*>(_digest)) << endl;
                }
            template<class MAC>
                void doMacDigest(string input)
                {
                    _alternateEncoder = true;
                    string mac;
                    size_t found = _algorithm.find("*");
                    string tempKey = _algorithm.substr(found + 1);
                    cout << "mac key: " << tempKey << endl;
                   // CryptoPP::SecByteBlock key(tempKey.length());
                    _keySize = tempKey.length();
                    cout << "_keySize: " << _keySize << endl;
                    _key = new byte[ _keySize ];
                    _key = (byte*) tempKey.c_str();
                    
                    _digestSize = MAC::DIGESTSIZE;
                    
                    cout << "_digestSize: " << _digestSize << endl;
                    
                    try
                    {
                            MAC xmac(_key, _keySize);		
                            CryptoPP::StringSource(input, true, 
                                    new CryptoPP::HashFilter(xmac,
                                            new CryptoPP::StringSink(mac)
                                    ) // HashFilter      
                            ); // StringSource
                            
                            _digest = new byte[ _digestSize ];
                            _digest = (byte*) mac.c_str();
                            cout << "mac: " << mac << endl;
                    }
                    catch(const CryptoPP::Exception& e)
                    {
                            cerr << e.what() << endl;
                            exit(1);
                    }
                }
            
            string getDigestHex();
            string getAlternateDigestHex();
            string getDigestBase64();
            string base64_encode(unsigned char const*, unsigned int);

            string _algorithm;
            string _outputEncoding;
            byte* _digest;
            byte* _key;
            size_t _digestSize;
            size_t _keySize;
            bool _ready;
            bool _alternateEncoder;
};

#endif
