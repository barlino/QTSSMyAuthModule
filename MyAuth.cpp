/*
    File:       MyAuth.cpp
    Contains:   Implementation of class defined in .h file
*/

#include "MyAuth.h"

char* MyAuth::GetReason( int iReasonCode, /* out */ char* szReason )
{
	switch( iReasonCode )
	{
		case INVALID_SIGNATURE_CODE:
			::strcpy( szReason, INVALID_SIGNATURE_STR );
			break;

		/* Add other reason codes here as needed */

		default:
			::strcpy( szReason, NO_ERROR_STR );
			break;
	}
	return szReason;
}

/*	This method should return NO_ERROR_CODE if URL is successfully authenticated (playback allowed)
	Else it should return one of the negative reason codes defined in the .h file
*/

int MyAuth::AuthenticateURL( const char* szURI, const char* szClientIP )
{
	/* Here, use the inputs (url & client ip) to make a decision: allow or decline.
	The code below demonstrates a oversimplified logic using only the url.
	To test this code, simply add a querystring parameter like this:
	a=declineme to the URL,	and see the play request getting turned down */

	if( strstr( szURI, "declineme" ) )
		return INVALID_SIGNATURE_CODE;

	return NO_ERROR_CODE;
}

