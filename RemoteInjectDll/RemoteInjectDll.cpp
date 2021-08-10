// RemoteInjectDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

#include "DataLog.h"

#pragma warning(disable : 4996)

#define QWORD unsigned long long int
#define PQWORD QWORD*

VOID HOOK();
VOID UNHOOK();

BOOL Hooked = FALSE;
CDataLog* m_pDataLog;

LPVOID pWebSocketSSL = NULL;

VOID SetWebSocketSSL(LPVOID ssl, void *buf, int len) {
	if (len > 17) {
		CHAR PartOfFirstRecvPacket[] = { 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x3a, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x00 };		//Upgrade:websocket
		PCHAR szData = new CHAR[len + 12];
		memset(szData, 0, len + 12);
		memcpy(szData, buf, len);			// buf中第num个字节未必是\x00，所以需要拷贝到szData中再调用strstr

		if (strstr(szData, PartOfFirstRecvPacket)) {
			pWebSocketSSL = ssl;
			m_pDataLog->LogFormatString(64, "[INFO] Find WebSocket SSL: 0x%llx\n\n", ssl);
		}
	}
}

BOOL IsWebSocketSSL(LPVOID pCurrentSSL) {
	if (pWebSocketSSL != NULL) {
		return pWebSocketSSL == pCurrentSSL;
	}
	return FALSE;
}


//定义如下结构，保存一次InlineHook所需要的信息
typedef struct _HOOK_DATA {
	char szApiName[128];		//待Hook的API名字
	char szModuleName[64];		//待Hook的API所属模块的名字
	int  HookCodeLen;			//Hook长度
	BYTE oldEntry[16];			//保存Hook位置的原始指令
	BYTE newEntry[16];			//保存要写入Hook位置的新指令
	ULONG_PTR HookPoint;		//待HOOK的位置
	ULONG_PTR JmpBackAddr;		//回跳到原函数中的位置
	ULONG_PTR pfnTrampolineFun;	//调用原始函数的通道
	ULONG_PTR pfnDetourFun;		//HOOK过滤函数
}HOOK_DATA, *PHOOK_DATA;
HOOK_DATA RecvHookData, SendHookData;


//等效于HOOK前的recv和send的函数的指针
typedef int (WINAPI *PFN_Recv)(LPVOID ssl, void *buf, int num);
typedef int (WINAPI *PFN_Send)(LPVOID ssl, const void *buf, int num);
// LPVOID ssl 原为ssl_st* ssl 或 SSL* ssl
// ssl_st与SSL是typedef关系
// 我应该用不到这个参数，所以直接转换成LPVOID
// ssl_st详见 https://docs.huihoo.com/doxygen/openssl/1.0.1c/structssl__st.html


//等效于HOOK前的recv和send的函数的指针
PFN_Recv OriginalRecv = NULL;
PFN_Send OriginalSend = NULL;


//int SSL_read(SSL *ssl, void *buf, int num);
//int SSL_write(SSL *ssl, const void *buf, int num)

//声明
int WINAPI My_Recv(LPVOID ssl, void *buf, int num);
int WINAPI My_Send(LPVOID ssl, const void *buf, int num);
BOOL Inline_InstallHook_Recv();
BOOL Inline_InstallHook_Send();
LPVOID GetAddress(char *, char *);
void InitHookEntry(PHOOK_DATA pHookData);
VOID InitTrampoline(PHOOK_DATA pHookData);
BOOL InstallCodeHook(PHOOK_DATA pHookData);



VOID HOOK() {
	if (Hooked) {
		return;
	}

	m_pDataLog = new CDataLog("d:\\桌面\\sanguosha.log");

	//MessageBoxA(0, "装载HOOK", "HOOK", 0);
	Inline_InstallHook_Send();
	Inline_InstallHook_Recv();
	Hooked = TRUE;
}


VOID UNHOOK() {
	//MessageBoxA(0, "卸载HOOK", "UNHOOK", 0);
}








int WINAPI My_Recv(LPVOID ssl, void *buf, int num)
{
	int ret = OriginalRecv(ssl, buf, num);
	if (ret > 0) {
		if (pWebSocketSSL == NULL) {
			SetWebSocketSSL(ssl, buf, ret);
		}

		if (IsWebSocketSSL(ssl)) {
			m_pDataLog->LogFormatString(64, "[PID:%d\tSSL:0x%llx] Recv Data (%d Bytes): \n", GetCurrentProcessId(), ssl, ret);
			m_pDataLog->LogHexData("", (PBYTE)buf, ret);
			m_pDataLog->LogString("\n\n");
		}
	}
	return ret;
}

int WINAPI My_Send(LPVOID ssl, const void *buf, int num)
{
	if (IsWebSocketSSL(ssl)) {
		m_pDataLog->LogFormatString(64, "[PID:%d\tSSL:0x%llx] Send Data (%d Bytes): \n", GetCurrentProcessId(), ssl, num);
		m_pDataLog->LogHexData("", (PBYTE)buf, num);
		m_pDataLog->LogString("\n\n");
	}

	return OriginalSend(ssl, buf, num);
}

BOOL Inline_InstallHook_Recv()
{
	m_pDataLog->LogFormatString(64, "[PID:%d FUNC:%s]\n", GetCurrentProcessId(), "SSL_read");

	ZeroMemory(&RecvHookData, sizeof(HOOK_DATA));
	strcpy_s(RecvHookData.szApiName, "SSL_read");
	strcpy_s(RecvHookData.szModuleName, "SGSOL.exe");
	RecvHookData.HookCodeLen = 15;
	RecvHookData.HookPoint = (ULONG_PTR)GetAddress(RecvHookData.szModuleName, RecvHookData.szApiName);//HOOK的地址
																									  //MsgBoxHookData.pfnOriginalFun = (PVOID)OriginalMessageBox;//调用原始函数的通道
																									  //x64下不能内联汇编了，所以申请一块内存用做TrampolineFun的shellcode

	m_pDataLog->LogFormatString(64, "HookPoint:\t0x%llx\n", RecvHookData.HookPoint);

	RecvHookData.pfnTrampolineFun = (ULONG_PTR)VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RecvHookData.pfnDetourFun = (ULONG_PTR)My_Recv;														//自定义hook函数
	BOOL result = InstallCodeHook(&RecvHookData);
	OriginalRecv = (PFN_Recv)RecvHookData.pfnTrampolineFun;												//相当于HOOK前的recv函数
	
	m_pDataLog->LogString("\n\n");
	return result;
}

BOOL Inline_InstallHook_Send()
{
	m_pDataLog->LogFormatString(64, "[PID:%d FUNC:%s]\n", GetCurrentProcessId(), "SSL_write");

	ZeroMemory(&SendHookData, sizeof(HOOK_DATA));
	strcpy_s(SendHookData.szApiName, "SSL_write");
	strcpy_s(SendHookData.szModuleName, "SGSOL.exe");
	SendHookData.HookCodeLen = 13;
	SendHookData.HookPoint = (ULONG_PTR)GetAddress(SendHookData.szModuleName, SendHookData.szApiName);	//HOOK的地址

	m_pDataLog->LogFormatString(64, "HookPoint:\t0x%llx\n", SendHookData.HookPoint);

	SendHookData.pfnTrampolineFun = (ULONG_PTR)VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	SendHookData.pfnDetourFun = (ULONG_PTR)My_Send;														//自定义hook函数
	BOOL result = InstallCodeHook(&SendHookData);
	OriginalSend = (PFN_Send)SendHookData.pfnTrampolineFun;												//相当于HOOK前的send函数

	m_pDataLog->LogString("\n\n");
	return result;
}

//获取指定模块中指定API的地址
LPVOID GetAddress(char* szModuleName, char *szFuncName)
{
	DWORD dwOffset = 0;

	if (strcmp(szFuncName, "SSL_write") == 0) {
		dwOffset = 0x14268EAD0 - 0x140000000;
	}
	if (strcmp(szFuncName, "SSL_read") == 0) {
		dwOffset = 0x14268E690 - 0x140000000;
	}

	HMODULE hModule = 0;
	if (hModule = GetModuleHandleA(szModuleName))
	{
		m_pDataLog->LogFormatString(64, "BaseAddr:\t0x%llx\n", (QWORD)hModule);
		m_pDataLog->LogFormatString(64, "Offset:\t\t0x%llx\n", (QWORD)dwOffset);
		return (LPVOID)((QWORD)hModule + (QWORD)dwOffset);
	}
	else
	{
		m_pDataLog->LogString("GetModuleHandleA失败");
	}
}

/*
填充入口点指令
使用的是mov rax xxxxx; jmp rax，长度12
为了清除指令碎屑，后面要跟着nop
*/
void InitHookEntry(PHOOK_DATA pHookData)
{
	if (strcmp(pHookData->szApiName, "SSL_write") == 0) {
		pHookData->newEntry[0] = 0x48;
		pHookData->newEntry[1] = 0xb8;
		*(ULONG_PTR*)(pHookData->newEntry + 2) = (ULONG_PTR)pHookData->pfnDetourFun;
		pHookData->newEntry[10] = 0xff;
		pHookData->newEntry[11] = 0xe0;
		pHookData->newEntry[12] = 0x90;
	}
	if (strcmp(pHookData->szApiName, "SSL_read") == 0) {
		pHookData->newEntry[0] = 0x48;
		pHookData->newEntry[1] = 0xb8;
		*(ULONG_PTR*)(pHookData->newEntry + 2) = (ULONG_PTR)pHookData->pfnDetourFun;
		pHookData->newEntry[10] = 0xff;
		pHookData->newEntry[11] = 0xe0;
		pHookData->newEntry[12] = 0x90;
		pHookData->newEntry[13] = 0x90;
		pHookData->newEntry[14] = 0x90;
	}
}


/*
构造从hook后的函数中回到原有函数的指令
由原来函数的入口点指令加上一个jmp构成
SSL_write原来的入口点指令：
.text:000000014268EAD0 41 56                                   push    r14
.text:000000014268EAD2 56                                      push    rsi
.text:000000014268EAD3 57                                      push    rdi
.text:000000014268EAD4 55                                      push    rbp
.text:000000014268EAD5 53                                      push    rbx
.text:000000014268EAD6 48 83 EC 40                             sub     rsp, 40h
.text:000000014268EADA 44 89 C6                                mov     esi, r8d
SSL_read原来的入口点指令：
.text:000000014268E690 56                                      push    rsi
.text:000000014268E691 57                                      push    rdi
.text:000000014268E692 53                                      push    rbx
.text:000000014268E693 48 83 EC 30                             sub     rsp, 30h
.text:000000014268E697 48 83 B9 98 00 00 00 00                 cmp     qword ptr [rcx+98h], 0
*/
VOID InitTrampoline(PHOOK_DATA pHookData)
{
	if (strcmp(pHookData->szApiName, "SSL_write") == 0) {
		//保存前13字节
		PBYTE pFun = (PBYTE)pHookData->pfnTrampolineFun;
		memcpy(pFun, (PVOID)pHookData->HookPoint, 13);

		//在后面添加一个跳转指令
		pFun += 13;					//跳过前几条指令
		pFun[0] = 0xFF;
		pFun[1] = 0x25;
		*(ULONG_PTR*)(pFun + 6) = pHookData->JmpBackAddr;
	}
	
	if (strcmp(pHookData->szApiName, "SSL_read") == 0) {
		//保存前15字节
		PBYTE pFun = (PBYTE)pHookData->pfnTrampolineFun;
		memcpy(pFun, (PVOID)pHookData->HookPoint, 15);

		//在后面添加一个跳转指令
		pFun += 15;					//跳过前几条指令
		pFun[0] = 0xFF;
		pFun[1] = 0x25;
		*(ULONG_PTR*)(pFun + 6) = pHookData->JmpBackAddr;
	}
}


BOOL CheckEntry(PHOOK_DATA pHookData) {
	BOOL bResult = FALSE;

	if (strcmp(pHookData->szApiName, "SSL_write") == 0) {
		m_pDataLog->LogHexData("原入口点指令：\n", pHookData->oldEntry, 13);

		BYTE Code[13] = { 0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x40,
			0x44, 0x89, 0xC6 };
		for (int i = 0; i < 13; i++) {
			if (pHookData->oldEntry[i] != Code[i]) {
				break;
			}
		}
		bResult = TRUE;
	}

	if (strcmp(pHookData->szApiName, "SSL_read") == 0) {
		m_pDataLog->LogHexData("原入口点指令：\n", pHookData->oldEntry, 15);

		BYTE Code[15] = { 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x83, 0xB9,
			0x98, 0x00, 0x00, 0x00, 0x00 };
		for (int i = 0; i < 15; i++) {
			if (pHookData->oldEntry[i] != Code[i]) {
				break;
			}
		}
		bResult = TRUE;
	}
	
	return bResult;
}


BOOL InstallCodeHook(PHOOK_DATA pHookData)
{
	SIZE_T dwBytesReturned = 0;
	HANDLE hProcess = GetCurrentProcess();
	BOOL bResult = FALSE;
	if (pHookData == NULL
		|| pHookData->HookPoint == 0
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->pfnTrampolineFun == NULL)
	{
		return FALSE;
	}
	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodeLen;
	LPVOID OriginalAddr = (LPVOID)pHookData->HookPoint;
	//printf("Address To HOOK=0x%p\n", OriginalAddr);
	InitHookEntry(pHookData);						//填充Inline Hook代码
	InitTrampoline(pHookData);						//构造Trampoline
	if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned))	//读取并保存原有入口点的几条指令
	{
		if (CheckEntry(pHookData)) {
			if (WriteProcessMemory(hProcess, OriginalAddr, pHookData->newEntry, pHookData->HookCodeLen, &dwBytesReturned))
			{
				m_pDataLog->LogString("HOOK成功！\n");
				bResult = TRUE;
			}
			else {
				m_pDataLog->LogString("WriteProcessMemory失败\n");
			}
		}
		else {
			m_pDataLog->LogString("CheckEntry失败\n");
		}
	}
	else {
		m_pDataLog->LogString("ReadProcessMemory失败\n");
	}
	return bResult;
}