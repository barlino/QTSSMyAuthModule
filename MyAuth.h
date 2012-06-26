/*
	File:		MyAuth.h
	Contains:	Code for Authenticating URLs
*/

#ifndef _MY__AUTH_H_
#define _MY__AUTH_H_
#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include "QTSSModuleUtils.h"

#define		MAX_AUTH_DECLINE_REASON		512
#define		NO_ERROR_STR				"No Error"
#define		NO_ERROR_CODE				0
#define		INVALID_TICKET_STR		"Ticket is expired"
#define		INVALID_TICKET_CODE		-1
/* Add other reason strings and codes, all of them should be les than zero */

class MyAuth
{
public:
	static char* GetReason( int iReasonCode, /* out */ char* szReason );
	MyAuth(QTSS_ModulePrefsObject);
	int authorizeTicket();
  Bool16 setRTSPParam( QTSS_StandardRTSP_Params *);
private:
  QTSS_Error theErr;	
  char* remoteAddr;
  char* absoluteURL;
	char* sessionID;
  char* fullRequest;
  char* queryString;
  char* filePath;

	MYSQL *conn;
	char* db_host;
	char* db_user;
	char* db_password;
	char* db_name;
	char sql[512];

  char ticket[512];
	void getTicket();
};

#endif // _MY__AUTH_H_
