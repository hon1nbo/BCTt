/************************************************************
* File: signingParameter.cpp
* 
* Provides the implementation of the signingParameter objects
*
* Author: Hon1nbo
*************************************************************/

#include "signingParameter.h"

using namespace std;

/* constructors for various cases */

signingParameter::signingParameter()
{
    _parameterIdentifier = "";
    _parameterValue = "";
}

signingParameter::signingParameter(string parameterIdentifier)
{
    _parameterIdentifier = parameterIdentifier;
    _parameterValue = "";
}

signingParameter::signingParameter(string identifier, string value)
{
    _parameterIdentifier = identifier;
    _parameterValue = value;
}

signingParameter::~signingParameter()	{	}

/*****************************************************************************
 * setParameterIdentifier sets the value used to identify a signing parameter
 * in the actual parsed message
 ****************************************************************************/

void signingParameter::setParameterIdentifier(string parameterIdentifier)
{
	_parameterIdentifier = parameterIdentifier;
}

/************************************************************
 * getParameterIdentifier returns the value used to identify
 * a signing parameter
 ***********************************************************/

string signingParameter::getParameterIdentifier()
{
	return _parameterIdentifier;
}

/***********************************************************************
 * setParameterValue stores the data read from the message as the value
 * used for signing
 **********************************************************************/

void signingParameter::setParameterValue(string parameterValue)
{
	_parameterValue = parameterValue;
}

/***********************************************************************
 * getParameterValue returns a string containing the stored value for a 
 * signing parameter
 **********************************************************************/

string signingParameter::getParameterValue()
{
	return _parameterValue;
}
