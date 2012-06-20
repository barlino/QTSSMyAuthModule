/*
    File:       QTSSMyAuthModule.cpp
    Contains:   Module that authenticates rtsp url-s
 */

#include "QTSSModuleUtils.h"
#include "MyAuth.h"
#include "QTSSMyAuthModule.h"

#define	MY_AUTH_MODULE_DEBUGGING 1

// STATIC DATA
static QTSS_ServerObject	sServer		= NULL;
static QTSS_ModulePrefsObject	sPrefs		= NULL;
static QTSS_StreamRef		sErrorLog	= NULL;
static MyAuth*		sObjMyAuth	= NULL;

// Attributes
static char*			sIsFirstRequestName_RTSPSession	= "QTSSMyAuthIsFirstRequest_SS";
static QTSS_AttributeID		sIsFirstRequestAttr_RTSPSession	= qtssIllegalAttrID;
static Bool16			sTrue				= true;

// Module description and version
static char*	sDescription	=	"Provides support for custom authentication of URL-s";
static UInt32	sVersion	=	0x00010000;

// Module preferences and their defaults
static Bool16	sEnabled	=	false;
static Bool16	kDefaultEnabled	=	false;

// FUNCTIONS
static QTSS_Error	QTSSMyAuthDispatch(QTSS_Role inRole, QTSS_RoleParamPtr inParams);
static QTSS_Error	Register(QTSS_Register_Params* inParams);
static QTSS_Error	Initialize(QTSS_Initialize_Params* inParams);
static QTSS_Error	RereadPrefs();
static QTSS_Error	AuthorizeRequest(QTSS_StandardRTSP_Params* inParams);
static QTSS_Error	DeInitialize();

// FUNCTION IMPLEMENTATIONS
QTSS_Error QTSSMyAuthModule_Main(void* inPrivateArgs)
{
    return _stublibrary_main(inPrivateArgs, QTSSMyAuthDispatch);
}

QTSS_Error QTSSMyAuthDispatch(QTSS_Role inRole, QTSS_RoleParamPtr inParams)
{
    switch (inRole)
    {
        case QTSS_Register_Role:
            return Register(&inParams->regParams);
        case QTSS_Initialize_Role:
            return Initialize(&inParams->initParams);
        case QTSS_RereadPrefs_Role:
            return RereadPrefs();
	case QTSS_RTSPAuthorize_Role:
	{
		if (!sEnabled) break;
		return AuthorizeRequest(&inParams->rtspAuthParams);
	}
	case QTSS_Shutdown_Role:
		return DeInitialize();
    }
    return QTSS_NoErr;
}


QTSS_Error Register(QTSS_Register_Params* inParams)
{
	// Do role & attribute setup
	(void)QTSS_AddRole(QTSS_Initialize_Role);
	(void)QTSS_AddRole(QTSS_RereadPrefs_Role);
    	(void)QTSS_AddRole(QTSS_RTSPAuthorize_Role);
    	(void)QTSS_AddRole(QTSS_Shutdown_Role);

	// Add an RTSP session attribute to track if the request is the first request of the session
	(void)QTSS_AddStaticAttribute(qtssRTSPSessionObjectType, sIsFirstRequestName_RTSPSession, NULL, qtssAttrDataTypeBool16);
	(void)QTSS_IDForAttr(qtssRTSPSessionObjectType, sIsFirstRequestName_RTSPSession, &sIsFirstRequestAttr_RTSPSession);

	// Tell the server our name!
	::strcpy(inParams->outModuleName, "QTSSMyAuthModule");
	return QTSS_NoErr;
}


QTSS_Error Initialize(QTSS_Initialize_Params* inParams)
{
	// Setup module utils
	QTSSModuleUtils::Initialize(inParams->inMessages, inParams->inServer, inParams->inErrorLogStream);

	// Get the server, prefs and error log objects
	sServer = inParams->inServer;
	sPrefs = QTSSModuleUtils::GetModulePrefsObject(inParams->inModule);
	sErrorLog = inParams->inErrorLogStream;
	sObjMyAuth = new MyAuth();

	// Set our version and description
	(void)QTSS_SetValue(inParams->inModule, qtssModDesc, 0, sDescription, ::strlen(sDescription));
	(void)QTSS_SetValue(inParams->inModule, qtssModVersion, 0, &sVersion, sizeof(sVersion));

	RereadPrefs();
	return QTSS_NoErr;
}


QTSS_Error RereadPrefs()
{
	QTSSModuleUtils::GetAttribute(sPrefs, "enabled", qtssAttrDataTypeBool16, &sEnabled, &kDefaultEnabled, sizeof(sEnabled));
	return QTSS_NoErr;
}

QTSS_Error AuthorizeRequest(QTSS_StandardRTSP_Params* inParams)
{
	// Step 1. Is this the first request of a session? Authentication needed only on first request, return QTSS_NoErr on subsequent calls
	Bool16 *isFirstRequest  = NULL;
	UInt32 theLen = sizeof(isFirstRequest);

	(void)QTSS_GetValuePtr(inParams->inRTSPSession, sIsFirstRequestAttr_RTSPSession, 0, (void**)&isFirstRequest, &theLen);
	if (isFirstRequest == NULL)
		(void)QTSS_SetValue(inParams->inRTSPSession, sIsFirstRequestAttr_RTSPSession, 0, &sTrue, sizeof(sTrue));
	else
		return QTSS_NoErr;

	/* Step 2. Retrieve the URL: raw material #1 needed to authenticate a request */
	char* szURL = NULL;
	StrPtrLen theURI;
	(void)QTSS_GetValuePtr(inParams->inRTSPRequest, /* qtssRTSPReqURI */ qtssRTSPReqAbsoluteURL, 0, (void**)&theURI.Ptr, &theURI.Len);
	const char* tmpPtr = strstr( theURI.Ptr, " RTSP/1.0" );
	UInt32 iSizeOfURL = (UInt32) (tmpPtr - theURI.Ptr);
	szURL = (char*) QTSS_New( (FourCharCode) QTSS_Milliseconds(), iSizeOfURL + 1 );
	::strncpy( szURL, theURI.Ptr, iSizeOfURL );
	szURL[ iSizeOfURL ] = 0;

	/* Step 3. Retrieve the Client IP Address: raw material #2 needed to authenticate a request */
	StrPtrLen theClientIP;
	(void)QTSS_GetValuePtr(inParams->inRTSPSession, qtssRTSPSesRemoteAddrStr, 0, (void**)&theClientIP.Ptr, &theClientIP.Len);

	/* Step 4. Log the entire URI if debug logging is turned on */
	/* Possible values for /etc/streaming/streamingserver.xml "error_logfile_verbosity" entry:
	qtssFatalVerbosity = 0, qtssWarningVerbosity = 1, qtssMessageVerbosity = 2, qtssAssertVerbosity = 3, qtssDebugVerbosity = 4	*/

	(void)QTSS_Write(sErrorLog, theURI.Ptr, theURI.Len, NULL, qtssDebugVerbosity);

	/* Step 5. Authenticate */
	SInt32 iAuthRes = sObjMyAuth->AuthenticateURL( szURL, theClientIP.Ptr );
	if( iAuthRes != NO_ERROR_CODE )
	{
		char szReason[ MAX_AUTH_DECLINE_REASON ];
		StrPtrLen clientMsg( MyAuth::GetReason( iAuthRes, szReason ) );

		char* szError = (char*) QTSS_New( (FourCharCode) QTSS_Milliseconds(), ::strlen( szURL ) + theClientIP.Len + MAX_AUTH_DECLINE_REASON + 100 );
		::sprintf( szError, "MyAuthModule: Authentication declined, reason: [%s], c-ip: [%s], url: [%s]", szReason, theClientIP.Ptr, szURL );
		(void)QTSS_Write(sErrorLog, szError, ::strlen( szError ), NULL, qtssMessageVerbosity);

		QTSS_Delete( (void*) szError );
		QTSSModuleUtils::SendErrorResponseWithMessage(inParams->inRTSPRequest, qtssClientUnAuthorized, &clientMsg);
	}
	QTSS_Delete( (void*) szURL );
	return QTSS_NoErr;
}

QTSS_Error DeInitialize()
{
	//Free or delete stuff here...
	delete sObjMyAuth;
	return QTSS_NoErr;
}

