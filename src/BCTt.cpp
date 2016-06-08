/**************************************************************************
* File: BCTt.cpp
* 
* This is a basic message editing and signing tool.
* It's purpose is to interface with the "Belch" Burp Extension
* to provide re-signing for signed messages that have been tampered with
* it requires some configuration for each message signing method.
* A sample configuration file is provided
* Cryptographic functions are provided by Crypto++
* 
* Author: Hon1nbo
***************************************************************************/

#include <iostream>
#include <cstdlib>
#include <fstream>
#include <string>
#include "string.h"
#include "signatureConfig.h"

#ifdef _WIN32
        #include "windows.h"
#endif

using namespace std;

void executeSigning(char*, char*);

int main(int argc, char* argv[])
{
    string filePath = argv[1];
    string configFilePathStr = "";
    char* configFilePath = (char*) configFilePathStr.c_str();
    if (argc > 2)
            configFilePath = argv[2];

    cout << "File Path: " << filePath << endl;

    executeSigning((char*)filePath.c_str(), configFilePath);
    
    cout << "Terminating." << endl;

    return 0;
}

/********************************************************
* executeSigning creates a signatureConfig object, 
* and uses it to sign the tampered message
* It then re-writes the message with the new signature.
*********************************************************/

void executeSigning(char* filePath, char* configFilePath)
{
    signatureConfig signer;
    if (configFilePath != "")
            signer.setConfigFilePath(configFilePath);

    signer.parseConfigFile();

    string signatureOutput = signer.createSignature(filePath);
    string oldSignature = signer.getOldSignature();
    string signatureParameter = signer.getSignatureParameter();

    // now we have to find and replace the original signature in the file.

    string search_string = signatureParameter + oldSignature;

    cout << search_string << endl;

    string replace_string = signatureParameter + signatureOutput;

    cout << replace_string << endl;

    string inbuf = "";

    ifstream messageFile;
    messageFile.open(filePath);
    ofstream tempFileOut("temp_message.txt");

    if (!messageFile.is_open() )
    {
            cerr << "Error opening message file for signature replacement!" << endl;
    }
      else
      {
        getline(messageFile, inbuf);    // have one before the while loop to prime it to fix eof problems
        
        while (!messageFile.eof())
        {
          int spot = inbuf.find(search_string);
          if(spot >= 0)
          {
            string tmpstring = inbuf.substr(0,spot);
            tmpstring += replace_string;
            tmpstring += inbuf.substr(spot+search_string.length(), inbuf.length());
            inbuf = tmpstring;
          }

          tempFileOut << inbuf << endl;
          getline(messageFile, inbuf);
        }

        messageFile.close();
      }

    tempFileOut.close();

    ifstream tempFileIn;
    tempFileIn.open("temp_message.txt");

    ofstream messageFileNew;
    messageFileNew.open(filePath);

    if (!tempFileIn.is_open() || !messageFileNew.is_open())
    {
        cerr << "Error opening temporary message file!" << endl;
        exit(1);
    }
    else
    {
        getline(tempFileIn, inbuf);
        
        while (!tempFileIn.eof())
        {
            messageFileNew << inbuf << endl;
            getline(tempFileIn, inbuf);
        }
    }

    tempFileIn.close();
    messageFileNew.close();
    
    cout << "Done." << endl;
}

