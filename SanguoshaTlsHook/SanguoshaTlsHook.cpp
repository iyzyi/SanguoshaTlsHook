// SanguoshaTlsHook.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

#include "stdlib.h"
#include "windows.h"

#include <Tlhelp32.h>
#include <Shlwapi.h>  
#pragma comment(lib, "shlwapi.lib")

#include "iostream"
#include "atlconv.h"

#include <assert.h>

#define PROCESS_ID_LIST_NUMBER 24

DWORD GetProcessIDByName(PWCHAR pwszName, PDWORD ProcessIdList)
{
	DWORD dwProcessIdNumbers = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe))
	{
		if (wcscmp(pe.szExeFile, pwszName) == 0)
		{
			assert(dwProcessIdNumbers + 1 <= PROCESS_ID_LIST_NUMBER);
			ProcessIdList[dwProcessIdNumbers] = pe.th32ProcessID;
			dwProcessIdNumbers++;
		}
		//USES_CONVERSION;
		//printf("%d\t%s\n", pe.th32ProcessID, W2A(pe.szExeFile));
	}
	CloseHandle(hSnapshot);
	return dwProcessIdNumbers;
}



int RemoteInject(DWORD dwPid) {
	HANDLE	hThread;
	HANDLE	hProcess;								//Զ�̽��̾��;
	CHAR	szLibPath[] = "D:\\����\\SanguoshaTlsHook\\x64\\Debug\\RemoteInjectDll.dll";		// "���dll"���ļ�������ȫ·��;
	void*   pLibRemote;								// szLibPath ��Ҫ���Ƶ���ַ
	DWORD   hLibModule;								//�Ѽ��ص�DLL�Ļ���ַ��HMODULE��;
	HMODULE hKernel32;
	CHAR	szLoadLibrary[] = "LoadLibraryA";


	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);

	//�����ڴ�;
	pLibRemote = ::VirtualAllocEx(hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE);
	//printf("%d\t\t%x\n", hProcess, pLibRemote);

	//д��������ڴ���;
	::WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath, sizeof(szLibPath), NULL);

	hKernel32 = ::GetModuleHandleA("Kernel32");
	FARPROC pLoadLibraryAddress = GetProcAddress(hKernel32, szLoadLibrary);
	//printf("%x\n", pLoadLibraryAddress);

	// ���� DLL.dll ��Զ�̽�����
	hThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryAddress, pLibRemote, 0, NULL);
	//if (hThread == NULL) {
	//	printf("3");
	//}
	//�ȴ�����
	::WaitForSingleObject(hThread, INFINITE);
	//ȡ��DLL�Ļ���ַ
	::GetExitCodeThread(hThread, &hLibModule);
	//�رվ��
	::CloseHandle(hThread);
	//�ͷ��ڴ�
	::VirtualFreeEx(hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE);




	//pTest test = (pTest)GetProcAddress(hLibModule, "test");

	return 0;
}



int main()
{
	DWORD ProcessIdList[PROCESS_ID_LIST_NUMBER];
	//DWORD dwProcessIdNumbers = GetProcessIDByName(L"SGSOL.exe", ProcessIdList);
	DWORD dwProcessIdNumbers = GetProcessIDByName(L"notepad.exe", ProcessIdList);
	printf("%d\n", dwProcessIdNumbers);

	for (DWORD i = 0; i < dwProcessIdNumbers; i++) {
		printf("pid=%d\n", ProcessIdList[i]);
		RemoteInject(ProcessIdList[i]);
		//InjectDll(ProcessIdList[i], "D:\\����\\SanguoshaTlsHook\\x64\\Debug\\RemoteInjectDll.dll");
		//printf("%d\n", bRet);
	}


	system("pause");

    return 0;
}

