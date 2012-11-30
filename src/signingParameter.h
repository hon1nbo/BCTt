/**********************************************************
* File: signingParameter.h
* 
* Interface for the signingParameter class.
* used to provide a structure for configurable parameters
* used to sign messages.
*
* Author: James (Jimmy) Hartnett
***********************************************************/


#ifndef signingParameter_h
#define signingParameter_h

#include <string>

using namespace std;

class signingParameter
{
	public:
		signingParameter();
		signingParameter(string);
		signingParameter(string, string);
		~signingParameter();
		
		void setParameterIdentifier(string);
		string getParameterIdentifier();
		
		void setParameterValue(string);
		string getParameterValue();

	private:
		string _parameterIdentifier;
		string _parameterValue;
};

#endif