/**************************************************************************
* File: signatureConfig.h
*
* This provides the interface for the configuration and 
* actual signing of the final message.
* It uses a configuration file to create the appropriate signing.
* An example configuration file is provided in the root of the BCTt folder.
*
* Author: James (Jimmy) Hartnett
***************************************************************************/

#ifndef signatureConfig_h
#define signatureConfig_h

#include <string>
#include <vector>
#include <fstream>
#include "signatureAlgorithm.h"
#include "signingParameter.h"

using namespace std;

class signatureConfig
{
    public:
            signatureConfig();
            signatureConfig(char*);
            ~signatureConfig();

            void setConfigFilePath(char*);
            void parseConfigFile();

            void addAlgorithm(string);
            void addParseParameter(string);
            void addPostParseParameter(string);
            void setDoFinalString(string);
            void setSignatureParameter(string);

            string createSignature(char*);
            string getOldSignature();
            string getSignatureParameter();

            void setTempFilePath(char*);
            char* getTempFilePath();
		
    private:
            vector<signatureAlgorithm*> _signatureAlgorithm;
            vector<signingParameter*> _parseParameter;
            vector<signingParameter*> _postParseParameter;
            vector<signingParameter*> _doFinalVector;

            string _doFinalString;
            string _signatureParameter;
            string _oldSignature;

            char* _tempFilePath;
            char* _configFilePath;

            ifstream _configFile;

            bool _error;
};

#endif