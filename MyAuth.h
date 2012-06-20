/*
	File:		MyAuth.h
	Contains:	Code for Authenticating URLs
*/

#ifndef _MY__AUTH_H_
#define _MY__AUTH_H_
#include <stdio.h>
#include <string.h>

#define		MAX_AUTH_DECLINE_REASON		32
#define		NO_ERROR_STR				"No Error"
#define		NO_ERROR_CODE				0
#define		INVALID_SIGNATURE_STR		"Signature is invalid"
#define		INVALID_SIGNATURE_CODE		-1
/* Add other reason strings and codes, all of them should be les than zero */

class MyAuth
{
public:
	static char* GetReason( int iReasonCode, /* out */ char* szReason );
	int AuthenticateURL( const char* szURI, const char* szClientIP );
private:
};

#endif // _MY__AUTH_H_
