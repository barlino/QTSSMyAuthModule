/*
        File:       QTSSMyAuthModule.h
        Contains:   Module that authenticates rtsp url-s
*/

#ifndef __QTSS_MYAUTH_MODULE_H__
#define __QTSS_MYAUTH_MODULE_H__

#include "QTSS.h"

extern "C"
{
    QTSS_Error QTSSMyAuthModule_Main(void* inPrivateArgs);
}

#endif // __QTSS_MYAUTH_MODULE_H__
