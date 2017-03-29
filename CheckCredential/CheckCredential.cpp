// CheckCredential.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "CheckCredential.h"

#if _DEBUG
BOOL	_bDebug = 1;
#else
BOOL	_bDebug = 0;
#endif
HANDLE	hLogFile = INVALID_HANDLE_VALUE;

TCHAR lpTargetPrefix[MAX_PATH] = TARGETPREFIX;

int _tmain(int argc, TCHAR *argv[])
{
	TCHAR MsgBuffer[BUFSIZ];
	DWORD cbWritten;
	HANDLE	hConOut;
	PCREDENTIAL *ppcred = NULL;;
 	DWORD dwNumCred;
	DWORD	hr;
	int		i;
	DWORD	dwError;
	DWORD	CredStateFlags;
	WORD	wAttrNorm;
	WORD	wAttrErr = (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_RED);

	hConOut = GetStdHandle(STD_OUTPUT_HANDLE);
	wAttrNorm = GetCurrentConsoleTextAttribute(hConOut);
	
	ParseArguments(argc, argv);

	StringCchPrintf( MsgBuffer, BUFSIZ, __T("Credential Check program version %s\r\n"), VERSION);
	_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
	memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));

#if _DEBUG
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


	//
	dwError = 0;
	for (i = 0; i < dwNumCred; i++) {
		//CredStateFlags = 0;
		CredStateFlags = InspectCredential(ppcred[i]);
		if (CredStateFlags & CREDBADPASSWORD) {
			SetConsoleTextAttribute(hConOut, wAttrErr);
			StringCchPrintf(MsgBuffer, BUFSIZ, __T(
				"---------------Error-------------------\r\n"
				"Bad password format is found\r\n"
				"---------------------------------------\r\n"));
			_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
			++dwError;
		}
		if (CredStateFlags & CREDTYPEMISMATCH) {
			SetConsoleTextAttribute(hConOut, wAttrErr);
			StringCchPrintf(MsgBuffer, BUFSIZ, __T(
				"---------------Error-------------------\r\n"
				"Credential Type mismatched\r\n"
				"---------------------------------------\r\n"));
			_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
			++dwError;
		}
		if (CredStateFlags & (USERNAMEMISMATCH | UPNURIMISMATCH)) {
			SetConsoleTextAttribute(hConOut, wAttrErr);
			StringCchPrintf(MsgBuffer, BUFSIZ, __T(
				"--------------Warning------------------\r\n"
				"Credential username mismatched with logon username\r\n"
				"---------------------------------------\r\n"));
			_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
			++dwError;
		}
		if ((CredStateFlags & (TYPESPECIFIC | PURPOSEOCS)) == (TYPESPECIFIC | PURPOSEOCS)) {
			SetConsoleTextAttribute(hConOut, wAttrErr);
			StringCchPrintf(MsgBuffer, BUFSIZ, __T(
				"---------------Error-------------------\r\n"
				"Specific credential is bad for OCS purpose\r\n"
				"---------------------------------------\r\n"));
			_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
			++dwError;
		}

		if ((CredStateFlags & (PURPOSEEWS | TYPESPECIFIC)) == (PURPOSEEWS | TYPESPECIFIC)) {
			if (!(CredStateFlags & USERNAMEISUPN)) {
				SetConsoleTextAttribute(hConOut, wAttrErr);
				StringCchPrintf(MsgBuffer, BUFSIZ, __T(
					"---------------Error-------------------\r\n"
					"EWS specific credential must required UPN username\r\n"
					"---------------------------------------\r\n"));
				_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
				memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
				++dwError;
			}
		}
		if (CredStateFlags & DAYS200OVEROLD) {
			SetConsoleTextAttribute(hConOut, wAttrErr);
			StringCchPrintf(MsgBuffer, BUFSIZ, __T(
				"--------------Warning------------------\r\n"
				"200 days over old\r\n"
				"---------------------------------------\r\n"));
			_WriteConsole(hConOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
			++dwError;

		}
		PrintCredential(hConOut, ppcred[i]);
		SetConsoleTextAttribute(hConOut, wAttrNorm);
	}

	// Clean up
	if (ppcred) {
		CredFree(ppcred);
	}
	if (hLogFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hLogFile);
	}
	//printf("Hit enter key!!\r\n");
	//getchar();
    return dwError;
}





void ParseArguments(int argc, TCHAR *argv[])
{
	int i,j;
	HANDLE	hlogfile;
	TCHAR  lpTemp[256];
	TCHAR  lpLogFile[BUFSIZ];
	PTSTR	lpOpt;
	TCHAR	szUpn[BUFSIZ];
	TCHAR	szUser[BUFSIZ];
	TCHAR	szDomain[BUFSIZ];

	for (i = 1; i < argc; i++) {
		if (lstrcmpi(argv[i], __T("/debug:no"))==0)
			_bDebug = 0;
		if (lstrcmpi(argv[i], __T("/debug:yes"))==0)
			_bDebug = 1;

		lpOpt = NULL;
		for (j = 0; j < 255; j++) {
			if ((argv[i][j] == __T(':'))&&(lpOpt==NULL)) {
				lpTemp[j] = __T('\0');
				lpOpt = &lpTemp[j+1];
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
		if (lstrcmp(lpTemp, __T("/logfilepath"))==0) {
			if ((lpOpt != NULL) && (*lpOpt != __T('\0'))) {
				StringCchCopy(lpLogFile, BUFSIZ, lpOpt);
				if (lpLogFile[lstrlen(lpLogFile)] == __T('\\')) {
					lpLogFile[lstrlen(lpLogFile)] = __T('\0');
				}
				GetUserNames(szUpn, szUser, szDomain);
				StringCchCat(lpLogFile, BUFSIZ, __T("\\CHECKLOG_"));
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