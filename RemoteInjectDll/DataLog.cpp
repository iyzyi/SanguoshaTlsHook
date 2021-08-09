#include "stdafx.h"
#include "DataLog.h"

#pragma warning(disable : 4996)

#define BUFFER_MAX_LENGTH 65536


CDataLog::CDataLog(PCHAR szLogFilePath) {
	fpLog = fopen(szLogFilePath, "a+b");
	if (fpLog == NULL) {
		MessageBoxA(NULL, "无法打开log文件", "错误", NULL);
	}

	bBuffer = new BYTE[BUFFER_MAX_LENGTH];			// 千万不要写成 new BYTE(BUFFER_MAX_LENGTH);这样写会crash.

	//InitializeCriticalSection(&m_cs);
}


CDataLog::~CDataLog() {
	fclose(fpLog);
	delete[] bBuffer;
	//DeleteCriticalSection(&m_cs);
}


VOID CDataLog::LogEnter() {
	fwrite("\n", 1, 1, fpLog);
}


VOID CDataLog::LogChar(PCHAR pbOneChar) {
	fwrite(pbOneChar, 1, 1, fpLog);
}

VOID CDataLog::LogChar(CHAR cData) {
	sprintf((PCHAR)bBuffer, "%c", cData);
	fwrite((PCHAR)bBuffer, 1, 1, fpLog);
}


VOID CDataLog::LogString(PCHAR szData) {
	//EnterCriticalSection(&m_cs);
	fwrite(szData, strlen(szData), 1, fpLog);
	//LeaveCriticalSection(&m_cs);
}


VOID CDataLog::LogHexString(PCHAR szPreString, PBYTE pbData, DWORD dwDataLen) {
	//EnterCriticalSection(&m_cs);

	fwrite(szPreString, strlen(szPreString), 1, fpLog);

	DWORD dwRow = 0, dwColumn = 0;
	for (dwRow = 0; dwRow < dwDataLen / 16 + 1; dwRow++) {
		for (dwColumn = 0; (dwRow * 16 + dwColumn < dwDataLen) && (dwColumn < 16); dwColumn++) {
			sprintf((PCHAR)bBuffer, "0x%02x ", pbData[dwRow * 16 + dwColumn]);
			LogString((PCHAR)bBuffer);
		}

		if (dwColumn != 16) {
			while (dwColumn < 16) {
				LogString("     ");
				dwColumn++;
			}
		}
		LogChar("\t");

		for (dwColumn = 0; (dwRow * 16 + dwColumn < dwDataLen) && (dwColumn < 16); dwColumn++) {
			DWORD dwIndex = dwRow * 16 + dwColumn;
			if (pbData[dwIndex] >= 32 && pbData[dwIndex] <= 126) {
				LogChar(pbData[dwIndex]);
			}
			else {
				LogChar(".");
			}
		}
		LogEnter();
	}

	//LeaveCriticalSection(&m_cs);
}
