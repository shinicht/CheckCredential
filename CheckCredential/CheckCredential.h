#pragma once

#define	VERSION		__T("1.07")
#define TARGET_TEMPLATE_EWS	__T("Microsoft_OC1:uri=%s:specific:EWS:1")
#define TARGET_TEMPLATE_OCS __T("Microsoft_OC1:uri=$s:specific:OCS:1")

// #define _WriteConsole		WriteConsole

#define TARGETPREFIX	__T("Microsoft_OC1")
#define TARGETFILTER	__T("Microsoft_OC1:*")

#define DAYS200OVEROLD		0x01000000
#define DAYS70OVEROLD		0x00200000
#define CREDBADPASSWORD		0x00100000
#define CREDTYPEMISMATCH	0x00010000
#define USERNAMEISUPN		0x00001000
#define USERNAMEISSAM		0x00002000
#define USERNAMEMISMATCH	0x00004000
#define	UPNURIMISMATCH		0x00000200
#define	UPNURIMATCH			0x00000100
#define UPNURIMASK			0x00000f00
#define TYPESPECIFIC		0x00000010
#define TYPECERTIFICATE		0x00000020
#define TYPEMASK			0x000000f0
#define PURPOSEOCS			0x00000001
#define PURPOSEEWS			0x00000002
#define PURPOSEMASK			0x0000000f
#define UNKNOWN				0x00000000

void ParseArguments(int argc, TCHAR *argv[]);
BOOL GetUserNames(LPTSTR szUpn, LPTSTR szUser, LPTSTR szDomain);
BOOL PrintCredential(HANDLE hOut, PCREDENTIAL pcred);
DWORD InspectCredential(PCREDENTIAL pcred);
WORD	GetCurrentConsoleTextAttribute(HANDLE hout);
ULARGE_INTEGER	CalcFileTimeDiffasSeconds(FILETIME ft1, FILETIME ft2);
DWORD	CalcFileTimeDiffasSecondsFromNow(FILETIME ft1);
BOOL	_WriteConsole(HANDLE hCon, CONST VOID *lpBuffer, DWORD nNumToWrite, LPDWORD lpNumofWritten, LPVOID lpReserve);