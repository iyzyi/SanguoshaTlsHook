#pragma once

#include "stdafx.h"
#include <stdio.h>
#include "windows.h"

class CDataLog {

public:

	FILE *fpLog = NULL;
	PBYTE bBuffer;
	//CRITICAL_SECTION m_cs;

	CDataLog(PCHAR szLogFilePath);

	~CDataLog();

	VOID LogEnter();

	VOID LogChar(PCHAR pbOneChar);

	VOID LogChar(CHAR cData);

	VOID LogString(PCHAR szData);

	VOID LogHexString(PCHAR szPreString, PBYTE pbData, DWORD dwDataLen);
};