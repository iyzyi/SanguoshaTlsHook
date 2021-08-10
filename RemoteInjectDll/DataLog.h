#pragma once

#include "stdafx.h"
#include "stdio.h"
#include "windows.h"
#include <share.h>
#pragma warning(disable : 4996)


#define BUFFER_MAX_LENGTH 65536


class CDataLog {

public:
	PBYTE bBuffer;
	FILE* fpLog = NULL;

	CDataLog(PCHAR szLogFilePath);
	~CDataLog();

	VOID LogString(PCHAR szData);
	VOID LogHexData(PCHAR szPreString, PBYTE pbData, DWORD dwDataLen);


private:
	//FILE *fpLog = NULL;
	//CRITICAL_SECTION m_cs;
	CHAR szLogFilePath[MAX_PATH];

	VOID OpenLogFile();
	VOID CloseLogFile();

	VOID __LogString(PCHAR szData);
	VOID __LogEnter();
	VOID __LogChar(PCHAR pbOneChar);
	VOID __LogChar(CHAR cData);
};