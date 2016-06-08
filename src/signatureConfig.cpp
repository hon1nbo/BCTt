/****************************************************************************
* File: signatureConfig.cpp
*
* This provides the implementation for the configuration and 
* actual signing of the final message.
* It uses a configuration file to create the appropriate signing.
* An example configuration file is provided in the root of the BCTt folder.
*
* Author: Hon1nbo
****************************************************************************/

#include "signatureConfig.h"
#include <cstdlib>
#include <iostream>

using namespace std;

signatureConfig::signatureConfig()
{
	string tempFilePath = "temp_message.txt";
	_tempFilePath = (char*)tempFilePath.c_str();
	_doFinalString = "";
	_signatureParameter = "";
	string configFilePath = "config.txt";
	_configFilePath = (char*)configFilePath.c_str();
        _oldSignature = "";
        _error = false;
}

signatureConfig::signatureConfig(char* filePath)
{
	signatureConfig();
	_configFilePath = filePath;
}

signatureConfig::~signatureConfig()
{
	// start by de-allocating dynamic memory from objects.

	for (int i = 0; i < _signatureAlgorithm.size(); i++)
		delete _signatureAlgorithm[i];
		
	for (int i = 0; i < _parseParameter.size(); i++)
		delete _parseParameter[i];

	for (int i = 0; i < _postParseParameter.size(); i++)
		delete _postParseParameter[i];
		
}

/**********************************
 * set the configuration file path
 *********************************/

void signatureConfig::setConfigFilePath(char* filePath)
{
	_configFilePath = filePath;
}

/************************************************************************
 * parseConfigFile opens and parses the data from the configuration file
 * and creates objects to sign a message as needed
 ***********************************************************************/

void signatureConfig::parseConfigFile()
{
	_configFile.open(_configFilePath);
	
	if (!_configFile.is_open())
        {
		cerr << "Could not open the configuration file!" << endl;
                _error = true;
        }
	else
	{
		string tempLine = "";
		size_t found = 0;
		
		// parse out the information needed for signing
		while (!_configFile.eof())
		{
			getline(_configFile, tempLine);
		
			if (tempLine.find("algorithm:") < tempLine.length())
			{
				found = tempLine.find("algorithm:");
				tempLine = tempLine.substr( (found + 10) );
                                tempLine = tempLine.substr(0, (tempLine.length() - 1));
				addAlgorithm(tempLine);
			}
			else if (tempLine.find("signatureParameter:") < tempLine.length())
			{
				found = tempLine.find("signatureParameter:");
				tempLine = tempLine.substr( (found + 19) );
                                tempLine = tempLine.substr(0, (tempLine.length() - 1));
				setSignatureParameter(tempLine);
			}
			else if (tempLine.find("parseParameter:") < tempLine.length())
			{
				found = tempLine.find("parseParameter:");
				tempLine = tempLine.substr( (found + 15) );
                                tempLine = tempLine.substr(0, (tempLine.length() - 1));
				addParseParameter(tempLine);
                                cout << "Parser Parameter: " << tempLine << endl;
			}
			else if (tempLine.find("postParseParameter:") < tempLine.length())
			{
				found = tempLine.find("postParseParameter:");
				tempLine = tempLine.substr( (found + 19) );
                                tempLine = tempLine.substr(0, (tempLine.length() - 1));
				addPostParseParameter(tempLine);
                                cout << "Post-Parse Parameter: " << tempLine << endl;
			}
			else if (tempLine.find("doFinalString:") < tempLine.length())
			{
				found = tempLine.find("doFinalString:");
				tempLine = tempLine.substr( (found + 14) );
                                //tempLine = tempLine.substr(0, (tempLine.length() - 1));
				setDoFinalString(tempLine);
			}
		}
		
		_configFile.close();
	
		// make sure we have enough information to execute a signing
		if (  ((int) _signatureAlgorithm.size() > 0) & ( ((int) _parseParameter.size() > 0) || ((int )_postParseParameter.size() > 0) ) & (_doFinalString != "") & (_signatureParameter != "") )
			_error = false;
		else
                {
			cerr << "Not enough information is parsed to sign a message!" << endl;
                        _error = true;
                }
	}
}

/************************************************************************
 * addAlgorithm just adds another crypto function to use on the message.
 * They can be daisy-chained through the config file
 ************************************************************************/

void signatureConfig::addAlgorithm(string algorithmName)
{
	signatureAlgorithm* temp = new signatureAlgorithm(algorithmName);
	_signatureAlgorithm.push_back(temp);	
}

/************************************************************************
 * addParseParameter inserts a value into a list of things to search for
 * while parsing the tampered data.
 ************************************************************************/

void signatureConfig::addParseParameter(string parameterIdentifier)
{
	signingParameter* temp = new signingParameter(parameterIdentifier);
	_parseParameter.push_back(temp);
}

/**********************************************************************
 * addPostParseParameter inserts a value into a list parameters that
 * are known before parsing, such as keys and device IDs.
 * The input string should be formatted along the lines of XXXXX:YYYYY
 **********************************************************************/

void signatureConfig::addPostParseParameter(string parameter)
{
	size_t found = 0;
	string parameterValue = "";
	string parameterIdentifier = "";
	
	found = parameter.find(':');
	
	if (found < parameter.length())
	{
		parameterIdentifier = parameter.substr(0, found);
		parameterValue = parameter.substr( (found + 1) );
                
                if (parameterValue[(parameterValue.length() - 1)] == ('\r' || '\n') )
                        parameterValue = parameterValue.substr(0, (parameterValue.length() - 1) );
	}
	
	if ( (parameterIdentifier != "") & (parameterValue != "") )
	{
		signingParameter* temp = new signingParameter(parameterIdentifier, parameterValue);
		_postParseParameter.push_back(temp);
	}
}

/********************************************************************
 * setDoFinalString sets the layout of the final string input to the
 * cryptographic functions
 *******************************************************************/

void signatureConfig::setDoFinalString(string finalStringLayout)
{
	_doFinalString = finalStringLayout;
}

/**********************************************************************
 * setSignatureParameter stores a value used to identify the signature
 * in the message
 *********************************************************************/

void signatureConfig::setSignatureParameter(string sigParameter)
{
	_signatureParameter = sigParameter;
}

/********************************************************************
 * createSignature(char*) takes a file path for a tampered message,
 * and signs it using the parsed configuration file.
 * It returns "ERROR" if the config file is not parsed or some other
 * error has occurred. 
 *******************************************************************/

string signatureConfig::createSignature(char* tamperedMessagePath)
{
    if (!_error)
    {
	size_t found = 0;
	
	ifstream tamperedMessage;
	tamperedMessage.open(tamperedMessagePath);
	
	if (!tamperedMessage.is_open())
		return NULL;
	else
	{
            // parse out the data from the message needed to re-sign it.

            string tempLineOrig = "";
            string tempLine = "";
            string parseParameter = "";
            int counter = 0;

            while (!tamperedMessage.eof())
            {
                getline(tamperedMessage, tempLineOrig);
                tempLine = tempLineOrig;

                if (counter < _parseParameter.size())
                {
                    parseParameter = _parseParameter[counter]->getParameterIdentifier();
                    found = tempLine.find(parseParameter);

                    if (found < tempLine.length())
                    {
                        tempLine = tempLine.substr( found + parseParameter.length() );
                        tempLine = tempLine.substr(0, (tempLine.length() - 1) );
                        _parseParameter[counter]->setParameterValue(tempLine);
                        counter++;
                    }
                }

                found = tempLine.find(_signatureParameter);
                if (found < tempLine.length())
                {
                    _oldSignature = tempLine.substr((found + _signatureParameter.length()));
                    _oldSignature = _oldSignature.substr(0, (_oldSignature.length() - 1) );
                }

                // if it is time to include the message body, 
                // loop through and get all of it

                if (_parseParameter[counter]->getParameterIdentifier() == "[BCTt:message_body]")
                {                            
                    if (tempLineOrig == "\r")
                    {
                        cout << "Parsing Message Body" << endl;

                        string messageBody = "";

                        // hate having a second while loop,
                        // but it saves code space and complexity
                        while (!tamperedMessage.eof()) 
                        {
                            getline(tamperedMessage, tempLine);
                            messageBody += tempLine;
                        }

                        _parseParameter[counter]->setParameterValue(messageBody);
                        counter++;
                    }
                }
            }

            string tempDoFinal = _doFinalString;
            string tempParameter = "";

            // parse out the parameters in the doFinalString and 
            // put their matching objects in an ordered vector for use.
            int element = 0;

            while (tempDoFinal.length() > 17)
            {                    
                found = tempDoFinal.find(".");

                tempParameter = tempDoFinal.substr(0, found);
                tempDoFinal = tempDoFinal.substr( (found + 1) );

                if (tempParameter != "")
                {
                    found = tempParameter.find("postParseParameter-");

                    if (found < tempParameter.length())
                    {
                        tempParameter = tempParameter.substr(19, 2);
                        element = atoi(tempParameter.c_str());
                        _doFinalVector.push_back(_postParseParameter[element]);
                    }
                    else
                    {
                        //parseParameter-
                        tempParameter = tempParameter.substr(15, 2);
                        element = atoi(tempParameter.c_str());
                        _doFinalVector.push_back(_parseParameter[element]);
                    }
                }
            }

            // form the final input to the algorithms

            string digest = "";

            for (int i = 0; i < _doFinalVector.size(); i++)
                digest.append(_doFinalVector[i]->getParameterValue());

            cout << "Final algorithm Input String: " << digest << endl;

            // execute all algorithms. 
            // Currently, we are assuming the algorithm only takes one input.

            for (int i = 0; i < _signatureAlgorithm.size(); i++)
            {
                _signatureAlgorithm[i]->createDigest(digest);
                digest = _signatureAlgorithm[i]->getDigest();
            }

            return digest;
	}
    }
    else
        return "ERROR";
}

/**********************************************************************
 * getOldSignature returns the old signature from the original message
 *********************************************************************/

string signatureConfig::getOldSignature()
{
	return _oldSignature;
}

/*************************************************************************
 * getSignatureParameter returns the value used to identify the signature
 * in the message
 ************************************************************************/

string signatureConfig::getSignatureParameter()
{
	return _signatureParameter;
}

/***************************************************************
 * setTempFilePath allows the use of a custom location and name
 * for the temporary message file
 **************************************************************/

void signatureConfig::setTempFilePath(char* filePath)
{
	_tempFilePath = filePath;
}

/*****************************************************************
 * getTempFilePath returns the name and location of the temporary
 * message file
 ****************************************************************/

char* signatureConfig::getTempFilePath()
{
	return _tempFilePath;
}
