// SanguoshaTlsHook.cpp : 定义控制台应用程序的入口点。
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
	HANDLE	hProcess;								//远程进程句柄;
	CHAR	szLibPath[] = "D:\\桌面\\SanguoshaTlsHook\\x64\\Debug\\RemoteInjectDll.dll";		// "你的dll"的文件名包含全路径;
	void*   pLibRemote;								// szLibPath 将要复制到地址
	DWORD   hLibModule;								//已加载的DLL的基地址（HMODULE）;
	HMODULE hKernel32;
	CHAR	szLoadLibrary[] = "LoadLibraryA";


	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);

	//分配内存;
	pLibRemote = ::VirtualAllocEx(hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE);
	//printf("%d\t\t%x\n", hProcess, pLibRemote);

	//写进分配的内存中;
	::WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath, sizeof(szLibPath), NULL);

	hKernel32 = ::GetModuleHandleA("Kernel32");
	FARPROC pLoadLibraryAddress = GetProcAddress(hKernel32, szLoadLibrary);
	//printf("%x\n", pLoadLibraryAddress);

	// 加载 DLL.dll 到远程进程中
	hThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryAddress, pLibRemote, 0, NULL);
	//if (hThread == NULL) {
	//	printf("3");
	//}
	//等待返回
	::WaitForSingleObject(hThread, INFINITE);
	//取得DLL的基地址
	::GetExitCodeThread(hThread, &hLibModule);
	//关闭句柄
	::CloseHandle(hThread);
	//释放内存
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
		//InjectDll(ProcessIdList[i], "D:\\桌面\\SanguoshaTlsHook\\x64\\Debug\\RemoteInjectDll.dll");
		//printf("%d\n", bRet);
	}


	system("pause");

    return 0;
}

