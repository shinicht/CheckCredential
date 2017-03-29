// CleanCredential.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "..\CheckCredential\CheckCredential.h"

BOOL IsCleanupTarget(DWORD flags);
void ParseArguments(int argc, TCHAR *argv[]);

#if _DEBUG
BOOL	_bDebug = 1;
#else
BOOL	_bDebug = 0;
#endif

BOOL	_bTestMode = FALSE;

HANDLE	hLogFile = INVALID_HANDLE_VALUE;

TCHAR lpTargetPrefix[MAX_PATH] = TARGETPREFIX;


int _tmain( int argc, TCHAR *argv[])
{
	TCHAR MsgBuffer[BUFSIZ];
	DWORD cbWritten;
	HANDLE	hConOut;
	WORD	wAttrNorm;
	WORD	wAttrErr = (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_RED);

	PCREDENTIAL *ppcred = NULL;;
	DWORD dwNumCred;
	DWORD	CredStateFlags;

	//DWORD	*CleanupTargetFlags;
	
	DWORD hr;
	DWORD dwError;
	TCHAR lpTargetPrefix[MAX_PATH] = TARGETPREFIX;


	hConOut = GetStdHandle(STD_OUTPUT_HANDLE);
	wAttrNorm = GetCurrentConsoleTextAttribute(hConOut);

	ParseArguments(argc, argv);

	StringCchPrintf(MsgBuffer, BUFSIZ, __T("Credential Clean program version %s\r\n"), VERSION);
	_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
	memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));

	/*
	PURPOSEOCS & TYPESPECIFIC & DAYS70OVEROLD 
	PURPOSEEWS & TYPESPECIFIC & USERNAMEISSAM
	CREDBADPASSWORD
	USERNAMEMISMATCH
	*/

#if _BUGBUG

	hr = CredEnumerate(_T("*"), 0, &dwNumCred, &ppcred);
#else
	hr = CredEnumerate(TARGETFILTER, 0, &dwNumCred, &ppcred);
#endif

	if (!hr) {
		dwError = GetLastError();
		switch (dwError) {
		case ERROR_NOT_FOUND:
			StringCchPrintf(MsgBuffer, BUFSIZ, __T("Credential Error %s\r\n"), _T("Target Credential is not found."));
			_WriteConsole(GetStdHandle(STD_ERROR_HANDLE), MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			break;
		case ERROR_NO_SUCH_LOGON_SESSION:
			StringCchPrintf(MsgBuffer, BUFSIZ, __T("Credential Error %s\r\n"), _T("No Logon Session"));
			_WriteConsole(GetStdHandle(STD_ERROR_HANDLE), MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			break;
		default:
			StringCchPrintf(MsgBuffer, BUFSIZ, __T("Credential Error %08x\r\n"), dwError);
			_WriteConsole(GetStdHandle(STD_ERROR_HANDLE), MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			break;
		}
		return -1;
	}

	memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));

	StringCchPrintf(MsgBuffer, BUFSIZ, __T("---------------------------------------\r\n"
	                          	           "%d Credentials found with %s prefix name\r\n"
		                                   "---------------------------------------\r\n"), dwNumCred, lpTargetPrefix);
	_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
	memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));

	int numdelete = 0;
	
	for (int i = 0; i < dwNumCred; i++) {
		//CredStateFlags = 0;
		CredStateFlags = InspectCredential(ppcred[i]);
		if (IsCleanupTarget(CredStateFlags)) {
			StringCchPrintf(MsgBuffer, BUFSIZ, __T("Delete Following Credential\r\n"));
			_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);

			PrintCredential(hConOut, ppcred[i]);
			if (!_bTestMode) {
				CredDelete(ppcred[i]->TargetName, ppcred[i]->Type, 0);
			}
			++numdelete;
		}
	}
	StringCchPrintf(MsgBuffer, BUFSIZ, __T("---------------------------------------\r\n"
		                                   "%d credential(s) Deleted\r\n"
		                                   "---------------------------------------\r\n"),numdelete);
	_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);

	return 0;
}


/*
PURPOSEOCS & TYPESPECIFIC & DAYS70OVEROLD
PURPOSEEWS & TYPESPECIFIC & USERNAMEISSAM
CREDBADPASSWORD
USERNAMEMISMATCH
*/

BOOL IsCleanupTarget(DWORD flags)
{
	if (flags & USERNAMEMISMATCH) {
		return TRUE;
	}
	if (flags & CREDBADPASSWORD) {
		return TRUE;
	}
	if (flags &TYPESPECIFIC) {
		if (flags & DAYS70OVEROLD) {
			return TRUE;
		}
		if (flags & PURPOSEEWS) {
			if (flags & USERNAMEISSAM) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

void ParseArguments(int argc, TCHAR *argv[])
{
	int i, j;
	HANDLE	hlogfile;
	TCHAR  lpTemp[256];
	TCHAR  lpLogFile[BUFSIZ];
	PTSTR	lpOpt;
	TCHAR	szUpn[BUFSIZ];
	TCHAR	szUser[BUFSIZ];
	TCHAR	szDomain[BUFSIZ];

	for (i = 1; i < argc; i++) {
		if (lstrcmpi(argv[i], __T("/debug:no")) == 0)
			_bDebug = 0;
		if (lstrcmpi(argv[i], __T("/debug:yes")) == 0)
			_bDebug = 1;

		if (lstrcmpi(argv[i], __T("/test")) == 0)
			_bTestMode = TRUE;

		lpOpt = NULL;
		for (j = 0; j < 255; j++) {
			if ((argv[i][j] == __T(':')) && (lpOpt == NULL)) {
				lpTemp[j] = __T('\0');
				lpOpt = &lpTemp[j + 1];
			}
			else if (argv[i][j] == __T('\0')) {
				lpTemp[j] = __T('\0');
			}
			else
			{
				lpTemp[j] = argv[i][j];
			}
		}
		CharLower(lpTemp);
		if (lstrcmp(lpTemp, __T("/logfilepath")) == 0) {
			if ((lpOpt != NULL) && (*lpOpt != __T('\0'))) {
				StringCchCopy(lpLogFile, BUFSIZ, lpOpt);
				if (lpLogFile[lstrlen(lpLogFile)] == __T('\\')) {
					lpLogFile[lstrlen(lpLogFile)] = __T('\0');
				}
				GetUserNames(szUpn, szUser, szDomain);
				StringCchCat(lpLogFile, BUFSIZ, __T("\\DELETELOG_"));
				StringCchCat(lpLogFile, BUFSIZ, szUser);
				StringCchCat(lpLogFile, BUFSIZ, __T(".TXT"));
				hlogfile = CreateFile(lpLogFile,
					GENERIC_WRITE,
					FILE_SHARE_WRITE,
					NULL,
					CREATE_ALWAYS,
					FILE_ATTRIBUTE_NORMAL,
					NULL);

				if (hlogfile != INVALID_HANDLE_VALUE) {
					hLogFile = hlogfile;

				}
				else
				{
					if (_bDebug) {
						TCHAR MsgBuffer[BUFSIZ];
						DWORD cbWritten;

						StringCchPrintf(MsgBuffer, BUFSIZ, __T("Log file creation failed Error %08x\r\nLog File Name : %s\r\n"),
							GetLastError(), lpLogFile);
						_WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);

					}
				}

			}
		}

	}
}