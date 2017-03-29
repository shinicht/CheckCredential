// UTil.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "CheckCredential.h"

extern BOOL	_bDebug;
extern HANDLE	hLogFile;

extern TCHAR lpTargetPrefix[];

BOOL GetUserNames(LPTSTR szUpn, LPTSTR szUser, LPTSTR szDomain)
{
	TCHAR	szName[BUFSIZ];
	ULONG	ulNameSiz;

	TCHAR MsgBuffer[BUFSIZ];
	DWORD cbWritten;
	int		i;

	ulNameSiz = BUFSIZ;
	if (!GetUserNameEx(NameUserPrincipal, szName, &ulNameSiz)) {
		szName[0] = __T('\0');
	}

	if (_bDebug) {
		StringCchPrintf(MsgBuffer, BUFSIZ, __T("User Principal Name : %s\r\n"), 
			(szName[0] == __T('\0')) ? __T("(null)") : szName);
		_WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
		memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
	}

	lstrcpyn(szUpn, szName, BUFSIZ);

	ulNameSiz = BUFSIZ;
	if (!GetUserNameEx(NameSamCompatible, szName, &ulNameSiz)) {
		return FALSE;
	}
	for (i = 0; i < ulNameSiz; i++) {
		if (szName[i] == __T('\\')) {
			szName[i] = __T('\0');
			break;
		}
	}
	if (i == ulNameSiz) {
		lstrcpyn(szUser, szName, BUFSIZ);
		ulNameSiz = BUFSIZ;
		GetUserNameEx(NameDnsDomain, szName, &ulNameSiz);
		lstrcpyn(szDomain, szName, BUFSIZ);
	}
	else
	{
		lstrcpyn(szDomain, szName, BUFSIZ);
		lstrcpyn(szUser, &(szName[i + 1]), BUFSIZ);
	}

	if (_bDebug) {
		StringCchPrintf(MsgBuffer, BUFSIZ, __T("Sam Account Name : %s\r\n"), szUser);
		_WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
		memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
		StringCchPrintf(MsgBuffer, BUFSIZ, __T("Domain Name : %s\r\n"), szDomain);
		_WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
		memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
	}

	return TRUE;
}


BOOL PrintCredential(HANDLE hOut, PCREDENTIAL pcred)
{
	TCHAR	MsgBuffer[BUFSIZ];
	DWORD	cbWritten;
	DWORD	credType;
	FILETIME	ftimelocal;
	SYSTEMTIME	sysTime;
	TCHAR	szTime[BUFSIZ];
	TCHAR	szDate[BUFSIZ];
	PTSTR	pszUserName;
	DWORD	dwLast;
#if _DEBUG
	DWORD	cbLength;
#endif

	static TCHAR *CredTypeStr[] = {
		__T("NULL"),								// 0
		__T("CRED_TYPE_GENERIC"),					// 1
		__T("CRED_TYPE_DOMAIN_PASSWORD"),			// 2
		__T("CRED_TYPE_DOMAIN_CERTIFICATE"),		// 3
		__T("CRED_TYPE_DOMAIN_VISIBLE_PASSWORD"),	// 4
		__T("CRED_TYPE_GENERIC_CERTIFICATE"),		// 5
		__T("CRED_TYPE_DOMAIN_EXTENDED"),			// 6
		__T("CRED_TYPE_MAXIMUM")					// 7
	};


	StringCchPrintf(MsgBuffer, BUFSIZ, __T("---------------------------------------\r\n"
		                                   "Target Name : %s\r\n"),
		pcred->TargetName
	);
	_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
	memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));

	if ((pcred->TargetAlias != NULL) && (*(pcred->TargetAlias) != __T('\0'))) {
		StringCchPrintf(MsgBuffer, BUFSIZ, __T("Target Alias    : %s\r\n"), pcred->TargetAlias);
		_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
		memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
	}

	if ((pcred->Comment != NULL) && (*(pcred->Comment) != __T('\0'))) {
		StringCchPrintf(MsgBuffer, BUFSIZ, __T("Comment    : %s\r\n"), pcred->Comment);
		_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
		memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
	}

	credType = min(pcred->Type, CRED_TYPE_MAXIMUM);
	StringCchPrintf(MsgBuffer, BUFSIZ, __T("Type    : %s\r\n"), CredTypeStr[credType]);
	_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
	memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));

	StringCchPrintf(MsgBuffer, BUFSIZ, __T("Credential Blob size    : %d\r\n"), pcred->CredentialBlobSize);
	_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
	memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));

	// User name conversion
	switch (pcred->Type) {
		case CRED_TYPE_GENERIC:
		case CRED_TYPE_DOMAIN_PASSWORD:
		case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
			pszUserName = pcred->UserName;
			break;

		case CRED_TYPE_DOMAIN_CERTIFICATE:
		case CRED_TYPE_GENERIC_CERTIFICATE:
			pszUserName = __T("(Use Certificate)");
			break;
		default:
			pszUserName = __T("Unknown");
			break;
	}
	if (pszUserName != NULL) {
		StringCchPrintf(MsgBuffer, BUFSIZ, __T("UserName    : %s\r\n"), pszUserName);
		_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
		memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
	}

	// time format conversion
	FileTimeToLocalFileTime(&(pcred->LastWritten), &ftimelocal);
	FileTimeToSystemTime(&ftimelocal, &sysTime);
	GetTimeFormat(LOCALE_USER_DEFAULT, 0, &sysTime, NULL, szTime, BUFSIZ);

	// date format conversion
	GetDateFormat(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &sysTime, NULL, szDate, BUFSIZ);

	dwLast = CalcFileTimeDiffasSecondsFromNow(ftimelocal);

	StringCchPrintf(MsgBuffer, BUFSIZ, __T("Last Written     : %s %s\r\n"
		                                   "(%u days %u hours %u minutes %u seconds before)\r\n"), 
		szDate,szTime,
		(dwLast/(60*60*24)),(dwLast/(60*60))%24,(dwLast/60) % 60,dwLast % 60);
	_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
	memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));


#if _DEBUG
	if (_bDebug) {
		if ((pcred->Type == CRED_TYPE_GENERIC) ||
			(pcred->Type == CRED_TYPE_DOMAIN_PASSWORD) ||
			(pcred->Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD)) {
			lstrcpy(MsgBuffer, __T("----------------------\r\nCredBlob "));
			cbLength = lstrlen(MsgBuffer) * sizeof(TCHAR) + pcred->CredentialBlobSize;
			lstrcpyn(&MsgBuffer[lstrlen(MsgBuffer)], (LPCTSTR)(pcred->CredentialBlob), pcred->CredentialBlobSize);
			MsgBuffer[(cbLength / sizeof(TCHAR))] = '\0';
			_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			StringCchPrintf(MsgBuffer, BUFSIZ, __T("\r\n----------------------\r\n"));
			_WriteConsole(hOut, MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
			memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
		}
	}
#endif

	return TRUE;
}

DWORD InspectCredential(PCREDENTIAL pcred)
{
	DWORD	dwflags = 0;
	TCHAR	szTargetName[BUFSIZ];
	PTSTR	szTemp;
	PTSTR	szPrefix = NULL;
	PTSTR	szUri = NULL;
	PTSTR	szType = NULL;
	PTSTR	szPurpose = NULL;
	TCHAR	szUpn[BUFSIZ];
	TCHAR	szUserName[BUFSIZ];
	TCHAR	szDomainName[BUFSIZ];
	int		cchLength;
	int		i;
	TCHAR MsgBuffer[BUFSIZ];
	DWORD cbWritten;

	lstrcpyn(szTargetName, pcred->TargetName, BUFSIZ);
	cchLength = lstrlen(szTargetName);
	szTemp = szTargetName;

	for (i = 0; i < cchLength; i++) {
		if (szTargetName[i] == __T(':')) {
			szTargetName[i] = __T('\0');
			if (lstrcmp(szTargetName, TARGETPREFIX) == 0) {
				szPrefix = szTemp;
				break;
			}
			else {
				szTemp = &szTargetName[i + 1];
			}
		}
	}
	for (szTemp = &szTargetName[++i]; i < cchLength; i++) {
		if (szTargetName[i] == __T(':')) {
			szTargetName[i] = __T('\0');

			if( (szTemp[0] == __T('u')) && 
				(szTemp[1] == __T('r')) &&
				(szTemp[2] == __T('i')) &&
				(szTemp[3] == __T('='))) {
				szUri = &szTemp[4];
				
			}
			break;
		}
	}
	for (szTemp = &szTargetName[++i]; i < cchLength; i++) {
		if (szTargetName[i] == __T(':')) {
			szTargetName[i] = __T('\0');
			szType = szTemp;
			break;
		}
	}
	for (szTemp = &szTargetName[++i]; i < cchLength; i++) {
		if (szTargetName[i] == __T(':')) {
			szTargetName[i] = __T('\0');
			szPurpose = szTemp;
			break;
		}
	}

	if (_bDebug) {
		StringCchPrintf(MsgBuffer, BUFSIZ, __T("Prefix : %s\r\nURI : %s\r\nType : %s\r\nPurpose : %s\r\n"),
			szPrefix, szUri, szType, szPurpose);
		_WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), MsgBuffer, lstrlen(MsgBuffer), &cbWritten, 0);
		memset(MsgBuffer, 0, BUFSIZ * sizeof(TCHAR));
	}

	GetUserNames(szUpn, szUserName, szDomainName);

	if(lstrcmpi(szUpn, szUri)==0) {
		dwflags |= UPNURIMATCH;
	}
	else {
		dwflags |= UPNURIMISMATCH;
	}
	if (lstrcmpi(szType, __T("specific")) == 0) {
		dwflags |= TYPESPECIFIC;
	}
	if (lstrcmpi(szType, __T("certificate")) == 0) {
		dwflags |= TYPECERTIFICATE;
	}
	if (lstrcmp(szPurpose, __T("EWS")) == 0) {
		dwflags |= PURPOSEEWS;
	}
	if (lstrcmp(szPurpose, __T("OCS")) == 0) {
		dwflags |= PURPOSEOCS;
	}

	switch (pcred->Type) {
		case CRED_TYPE_GENERIC:
		case CRED_TYPE_DOMAIN_PASSWORD:
			if (lstrcmpi(pcred->UserName, szUri) == 0) {
				dwflags |= USERNAMEISUPN;
			}
			if (lstrcmpi(pcred->UserName, szUserName) == 0) {
				dwflags |= USERNAMEISSAM;
			}
			if (!(dwflags & (USERNAMEISUPN | USERNAMEISSAM))) {
				dwflags |= USERNAMEMISMATCH;
			}

			if (!(dwflags&TYPESPECIFIC)) {
				dwflags |= CREDTYPEMISMATCH;
			}
			else
			{
				if (pcred->CredentialBlobSize == 0) {
					dwflags |= CREDBADPASSWORD;
				}
			}
			break;
		case CRED_TYPE_DOMAIN_CERTIFICATE:
		case CRED_TYPE_GENERIC_CERTIFICATE:
			if (!(dwflags&TYPECERTIFICATE)) {
				dwflags |= CREDTYPEMISMATCH;

				if (pcred->CredentialBlobSize == 0) {
					dwflags |= CREDBADPASSWORD;
				}
			}
			break;

	}
	if (CalcFileTimeDiffasSecondsFromNow(pcred->LastWritten) / (60 * 60 * 24) > 200) {
		dwflags |= DAYS200OVEROLD;
	}
	if (CalcFileTimeDiffasSecondsFromNow(pcred->LastWritten) / (60 * 60 * 24) > 71) {
		dwflags |= DAYS70OVEROLD;
	}
	return dwflags;
}

WORD GetCurrentConsoleTextAttribute(HANDLE hout)
{
	CONSOLE_SCREEN_BUFFER_INFO	co;

	if (GetConsoleScreenBufferInfo(hout, &co)) {
		return co.wAttributes;
	}
	else {
		return (FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);
	}

}


ULARGE_INTEGER	CalcFileTimeDiffasSeconds(FILETIME ft1, FILETIME ft2)
{
	ULARGE_INTEGER uliDiff;
	ULARGE_INTEGER uli1;
	ULARGE_INTEGER uli2;

	uli1.HighPart = ft1.dwHighDateTime;
	uli1.LowPart = ft1.dwLowDateTime;
	uli2.HighPart = ft2.dwHighDateTime;
	uli2.LowPart = ft2.dwLowDateTime;
	uliDiff.QuadPart = uli1.QuadPart - uli2.QuadPart;
	uliDiff.QuadPart /= 10000000;
	return uliDiff;
}

DWORD	CalcFileTimeDiffasSecondsFromNow(FILETIME ft1)
{
	FILETIME ftimeLocal;
	FILETIME ftimeNow;
	ULARGE_INTEGER liTimeDiff;

	GetSystemTimeAsFileTime(&ftimeNow);
	FileTimeToLocalFileTime(&ftimeNow, &ftimeLocal);
	liTimeDiff = CalcFileTimeDiffasSeconds(ftimeLocal, ft1);
	return liTimeDiff.LowPart;
}

BOOL	_WriteConsole(HANDLE hCon, CONST VOID *lpBuffer, DWORD nNumToWrite, LPDWORD lpNumofWritten, LPVOID lpReserve)
{
	BOOL hr;
	DWORD cbWritten;
	char	lpzAnsi[BUFSIZ];

	hr = WriteConsole(hCon, lpBuffer, nNumToWrite, lpNumofWritten, lpReserve);
	if (hLogFile != INVALID_HANDLE_VALUE) {
		CharToOem((LPTSTR)lpBuffer, lpzAnsi);
		WriteFile(hLogFile, lpzAnsi, lstrlenA(lpzAnsi) , &cbWritten, NULL);
	}
	return hr;
}
