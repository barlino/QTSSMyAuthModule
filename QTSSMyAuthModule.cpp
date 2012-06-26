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
	sObjMyAuth = new MyAuth(sPrefs);

	// Set our version and description
	(void)QTSS_SetValue(inParams->inModule, qtssModDesc, 0, sDescription, ::strlen(sDescription));
	(void)QTSS_SetValue(inParams->inModule, qtssModVersion, 0, &sVersion, sizeof(sVersion));

	QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, "QTSSMyAuthModule_Initialize");

	RereadPrefs();
	return QTSS_NoErr;
}


QTSS_Error RereadPrefs()
{
	QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, "QTSSMyAuthModule_RereadPrefs");
	QTSSModuleUtils::GetAttribute(sPrefs, "enabled", qtssAttrDataTypeBool16, &sEnabled, &kDefaultEnabled, sizeof(sEnabled));
  
	return QTSS_NoErr;
}

QTSS_Error AuthorizeRequest(QTSS_StandardRTSP_Params* inParams)
{
	QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, "QTSSMyAuthModule_AuthorizeRequest");
	// Step 1. Is this the first request of a session? Authentication needed only on first request, return QTSS_NoErr on subsequent calls
	Bool16 *isFirstRequest  = NULL;
	UInt32 theLen = sizeof(isFirstRequest);
	
	(void)QTSS_GetValuePtr(inParams->inRTSPSession, sIsFirstRequestAttr_RTSPSession, 0, (void**)&isFirstRequest, &theLen);
	if (isFirstRequest == NULL)
		(void)QTSS_SetValue(inParams->inRTSPSession, sIsFirstRequestAttr_RTSPSession, 0, &sTrue, sizeof(sTrue));
	else
		return QTSS_NoErr;

	sObjMyAuth->setRTSPParam(inParams);

	SInt32 iAuthRes = sObjMyAuth->authorizeTicket();
	if (iAuthRes != NO_ERROR_CODE)
	{
		char szReason[ MAX_AUTH_DECLINE_REASON ];
		StrPtrLen clientMsg( MyAuth::GetReason( iAuthRes, szReason ) );

		QTSSModuleUtils::SendErrorResponseWithMessage(inParams->inRTSPRequest, qtssClientUnAuthorized, &clientMsg);	
	}
	return QTSS_NoErr;
}


QTSS_Error DeInitialize()
{
	QTSSModuleUtils::LogErrorStr(qtssMessageVerbosity, "QTSSMyAuthModule_DeInitiaize");
	//Free or delete stuff here...
	delete sObjMyAuth;
	return QTSS_NoErr;
}

