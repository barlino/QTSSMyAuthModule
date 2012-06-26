/*
    File:       MyAuth.cpp
    Contains:   Implementation of class defined in .h file
*/

#include "MyAuth.h"
#include <stdio.h>
#include <mysql.h>

#define MY_AUTH_DEBUG 0

char* MyAuth::GetReason( int iReasonCode, /* out */ char* szReason )
{
	switch( iReasonCode )
	{
		case INVALID_TICKET_CODE:
			::strcpy( szReason, INVALID_TICKET_STR );
			break;

		/* Add other reason codes here as needed */

		default:
			::strcpy( szReason, NO_ERROR_STR );
			break;
	}
	return szReason;
}

int MyAuth::authorizeTicket()
{
	QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, "MyAuth::AuthorizeTicket()");

	conn = mysql_init(NULL);
	
	if(!mysql_real_connect(conn, db_host, db_user, db_password, db_name, 0, NULL, 0))
  {
  	qtss_printf("mysql_error: %s\n", mysql_error(conn));
		conn = NULL;
		exit(1);
  }

	int ticket_len = strlen(ticket);
  char ticket_str[ticket_len*2+1];
  mysql_real_escape_string(conn, ticket_str, ticket, ticket_len);
	snprintf(sql, 512, "SELECT COUNT(*) AS numrows FROM song WHERE id = '%s'", ticket_str);	
	if (MY_AUTH_DEBUG) {
		QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, sql);
	}
	mysql_query(conn, sql);

	MYSQL_RES *res = mysql_store_result(conn);
	MYSQL_ROW rows = mysql_fetch_row(res);
	mysql_free_result(res);
	mysql_close(conn);
	if (! atoi(rows[0]))
	{
		char* szError = (char*) QTSS_New( (FourCharCode) QTSS_Milliseconds(), MAX_AUTH_DECLINE_REASON + 100 );
		
		char szReason[ MAX_AUTH_DECLINE_REASON ];
    MyAuth::GetReason( INVALID_TICKET_CODE, szReason );
    ::sprintf( szError, "MyAuthModule: Authentication declined, reason: [%s], c-ip: [%s], url: [%s], queryString: [%s]", szReason, remoteAddr, absoluteURL, queryString );
		QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, szError);
		QTSS_Delete((void*)szError);
		return INVALID_TICKET_CODE;
	}
	conn = NULL;
	return NO_ERROR_CODE;
}

Bool16 MyAuth::setRTSPParam( QTSS_StandardRTSP_Params *inParams )
{
	theErr = QTSS_GetValueAsString(inParams->inRTSPSession, qtssRTSPSesID, 0, &sessionID);
	theErr = QTSS_GetValueAsString(inParams->inRTSPSession, qtssRTSPSesRemoteAddrStr, 0, &remoteAddr);
 	theErr = QTSS_GetValueAsString(inParams->inRTSPRequest, qtssRTSPReqFullRequest, 0, &fullRequest);
	theErr = QTSS_GetValueAsString(inParams->inRTSPRequest, qtssRTSPReqQueryString, 0, &queryString);
	theErr = QTSS_GetValueAsString(inParams->inRTSPRequest, qtssRTSPReqAbsoluteURL, 0, &absoluteURL);
	theErr = QTSS_GetValueAsString(inParams->inRTSPRequest, qtssRTSPReqFilePath, 0, &filePath);

	if (MY_AUTH_DEBUG) {
		QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, sessionID);
		QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, remoteAddr);
		QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, fullRequest);
		QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, queryString);
		QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, absoluteURL);
		QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, filePath);
	}
	getTicket();
	return 0;
}

void MyAuth::getTicket()
{
	char* _pair = ::strtok(queryString, "&");
	while(_pair) {
		if (strstr(_pair, "ticket")) {
			sscanf(_pair, "ticket=%[^&]s", ticket);
		}
		_pair = ::strtok(NULL, "&");
	}


	if (MY_AUTH_DEBUG) {
  	qtss_printf("ticket\t=> %s\n", ticket);
	}
}

MyAuth::MyAuth(QTSS_ModulePrefsObject inPrefs)
{
	db_host = QTSSModuleUtils::GetStringAttribute(inPrefs, "mysql_host", NULL);
	db_user = QTSSModuleUtils::GetStringAttribute(inPrefs, "mysql_user", NULL);
	db_password = QTSSModuleUtils::GetStringAttribute(inPrefs, "mysql_password", NULL);
	db_name = QTSSModuleUtils::GetStringAttribute(inPrefs, "mysql_name", NULL);

}

