/**************************************************************************************
** Burp Cryptographic Tamper tool (BCTt)
** Author: James (Jimmy) Hartnett
** Tool for performing cryptographic operations on messages intercepted with Burp
** Created to be called as a "external editor" using the "Belch" Burp Extension
** Current Status: Early Development
	Basic functionality is stable for real use, but feature set is currently limited.
**************************************************************************************/

# Reading Tip: this readme is laid out for syntax highlighters
# I use notepad++ with C++ highlighting enabled.

/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
 #Table of Contents:           *
                               *
 * Info                        *
 * Supported Functions         *
 * Limitations                 *
 * System Requirements         *
 * Usage                       *
 * Configuration               *
	*'algorithm'               *
	*'Parsing Parameters'      *
	*'Post-Parsing Parameters' *
	*'Do Final String'         *
 * TODOs                       *
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\


**************
#### Info ####
**************

Burp is a great tool for pen-testing client-server communications, but it has a big problem.
It cannot successfully tamper any message that has been signed or encrypted,
regardless of whether or not the user has all of the information needed.
So I created the Burp Cryptographic Tamper Tool (BCTt).

Once Burp intercepts a message, the Belch extension forwards the message to the BCTt, 
which is treated like a text or binary editor as far as Belch is concerned.
BCTt opens a text editor for tampering the messasge, as Belch prevents the native burp editor from being useful.
It is possible to have BCTt open different editors depending on the task at hand.
Given a configuration file of what to look for, BCTt will re-sign the message after it has been tampered.
Belch will then read the re-signed message, and forward it to Burp which in turn sends it to the server.


*****************************
#### Supported Functions ####
*****************************

BCTt currently supports the following cryptographic functions
The entire Crypto++ library is included other functions as well, and as development progresses more of it will be implemented by default.

# Cryptographic Hashing:
   *md5
   *md2
   *sha1
   *sha
   *sha256
   *sha384
   *sha512
   
# Output Encoding:
   * none
   * base64
   * hex
   
   
*********************
#### Limitations ####
*********************

* First and foremost, BCTt is NOT a tool for cracking signatures or encryption, and it probably never will be.
	It is intended to assist in testing server communications by trusted parties.
	If you want to actually test the security of the signatures themselves, there are other ways to go about that.
* It requires that the user have all information necessary to sign a message.
* Not running the latest Crypto++ due to some implementation changes not being reflected well in documentation.
* It does not currently support many algorithms, since it is still in early development.
* The configuration file can be a pain to format correctly, in the future I may switch to XML.
* It assumes the message body starts with a '\r' character. But this can be changed in code as needed.
* it currently does not have cross-platform support. This is coming in future updates.


*****************************
#### System Requirements ####
*****************************

* Windows (tested on Win7 Pro). Cross-platform support in future releases.
* Burp proxy (tested with free edition, Professional should work too)
* "Belch" Burp Extension
* a text editor that can be opened from batch file (by default code opens Notepad)


***************
#### Usage ####
***************

1) Ensure you have all information needed to sign a message.
2) Make a configuration file that suits your messages (see exampleConfig.txt and the information below for details)
3) Update BCTt.bat to include your configuration file and, if desired, change the cmd command to open an editor other than notepad.
4) When you open Burp with the Belch extension, set BCTt.bat as the External Editor of choice and tell it to intercept proxy requests (or responses depending on your use case)
5) When a message is intercepted, BCTt should open the editor specified (by default Notepad), and allow you to edit it.
	a) There is a limited time window to edit the message. Currently, this is hard-coded at 5 seconds in code. But this can be changed. 
		I am working on a config file that will have options like this to set.
6) When done editing, close the message in the text editor.
7) BCTt should automatically sign the message assuming everything is configured right, and the Belch runtime for it should end which triggers Burp to send the message.


***********************
#### Configuration ####
***********************

Please see exampleConfig.txt in the source directory for a sample layout, here I am explaining what each item means.

In all cases, Capitalization is important.

Order of these entries matters.

#####################
* algorithm:XXX:YYY *	* required *
#####################

	This sets a algorithm to use for signing or encrypting. This can occurr multiple times. It is chained in the order in which they are entered.
	The "XXX" should be replaced by whichever algorithm you intend to use. See the list of supported algorithms.
	The "YYY" should be replaced by the output encoding for byte stream of the algorithm you intend to use. (not the character encoding)
	If no output encoding should be used, then replace "YYY" with "none" (without quotes)
	
##############################
* signatureParameter:XXXXXXX *	* required *
##############################

	This sets the value used to identify the actual signature in the message. It may only be specified once.
	the "XXXXXX" should be replaced with the actual value, without quotes. If there is a space between the signature parameter and the actual signature, it should be included.
	
###########################
* parseParameter:XXXXXX *		* at least one if no postParseParameters are used
###########################

	This adds an identifier for a parameter contained in the message used in forming the signature, such as a username, timestamp, the message contents, etc.
	The "XXXXXX" should be replaced with whatever identifies the parameter, without quotes. If there is a space between the parameter and the actual value, it should be included.
	If there is more than one, they need to be entered in the order in which the occurr in the file.
	
	To specify the actual message body as a parse parameter, make your last parseParameter line:
	parseParameter:[BCTt:message_body]
	
##############################
* postParseParameter:XXX:YYY *	* at least one if no parseParameters are used
##############################

	This adds a parameter that is specified outside of the message itself. This includes keys stored on the client/server, passwords, etc.
	The "XXX" should be replaced by an identifier for the parameter, and the "YYY" with it's actual value.

###############################
* doFinalString:XXXX.YYY.ZZZ. *	* required *
###############################

	This specifies how the data should be formatted when sent to the algorithms for signing or encrypting.
	The parameters can either be:
		parseParameter-AA.
		or
		postParseParameter-AA.
	"AA" should be replaced by a two digit number identifying the number of the parameter used, based on the order of the parameters in the configuration file.
	
	**NOTE: The trailing '.' after each entry on the same line is necessary. This will be addressed in the future.


***************
#### TODOs ####
***************

* create a more intuitive configuration file base, like XML.
* upgrade to the latest Crypto++ library (currently running behind due to implementation changes compared to documentation).
* cross-platform support
* look into replacing string search if statment blocks with a Map.
* implement more of the Crypto++ library
* allow more parameters to be specified for crytpographic functions.