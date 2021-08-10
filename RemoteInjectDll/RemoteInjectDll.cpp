// RemoteInjectDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"

#include "DataLog.h"

#pragma warning(disable : 4996)

#define QWORD unsigned long long int

VOID HOOK();
VOID UNHOOK();

BOOL Hooked = FALSE;
CDataLog* m_pDataLog;


//�������½ṹ������һ��InlineHook����Ҫ����Ϣ
typedef struct _HOOK_DATA {
	char szApiName[128];		//��Hook��API����
	char szModuleName[64];		//��Hook��API����ģ�������
	int  HookCodeLen;			//Hook����
	BYTE oldEntry[16];			//����Hookλ�õ�ԭʼָ��
	BYTE newEntry[16];			//����Ҫд��Hookλ�õ���ָ��
	ULONG_PTR HookPoint;		//��HOOK��λ��
	ULONG_PTR JmpBackAddr;		//������ԭ�����е�λ��
	ULONG_PTR pfnTrampolineFun;	//����ԭʼ������ͨ��
	ULONG_PTR pfnDetourFun;		//HOOK���˺���
}HOOK_DATA, *PHOOK_DATA;
HOOK_DATA RecvHookData, SendHookData;


//��Ч��HOOKǰ��recv��send�ĺ�����ָ��
//typedef int (WINAPI *PFN_Recv)(SOCKET s, char *buf, int len, int flags);
typedef int (WINAPI *PFN_Send)(QWORD *ssl, const void *buf, int num);

//��Ч��HOOKǰ��recv��send�ĺ�����ָ��
//PFN_Recv OriginalRecv = NULL;
PFN_Send OriginalSend = NULL;


//int SSL_write(SSL *ssl, const void *buf, int num)

//����
//int WINAPI My_Recv(SOCKET s, char *buf, int len, int flags);
int WINAPI My_Send(QWORD *ssl, const void *buf, int num);
//BOOL Inline_InstallHook_Recv();
BOOL Inline_InstallHook_Send();
LPVOID GetAddress(char *, char *);
void InitHookEntry(PHOOK_DATA pHookData);
VOID InitTrampoline(PHOOK_DATA pHookData);
BOOL InstallCodeHook(PHOOK_DATA pHookData);



VOID HOOK() {
	if (Hooked) {
		return;
	}

	m_pDataLog = new CDataLog("d:\\����\\sanguosha.log");

	//MessageBoxA(0, "װ��HOOK", "HOOK", 0);
	Inline_InstallHook_Send();
	Hooked = TRUE;
}


VOID UNHOOK() {
	//MessageBoxA(0, "ж��HOOK", "UNHOOK", 0);
}








//int WINAPI My_Recv(SOCKET s, char *buf, int len, int flags)
//{
//	int ret = OriginalRecv(s, buf, len, flags);
//	if (ret > 0) {
//		if (RecvCallBack) {
//			RecvCallBack(s, buf, ret);
//		}
//	}
//	return ret;
//}

int WINAPI My_Send(QWORD *ssl, const void *buf, int num)
{
	/*int ret = OriginalSend(s, buf, len, flags);
	if (ret > 0) {
	if (SendCallBack) {
	SendCallBack(s, buf, ret);
	}
	}
	return ret;*/
	//MessageBoxA(NULL, "send", "", NULL);

	
	//m_pDataLog->LogString("call My_Send\n");
	m_pDataLog->LogString("Send Data:\n");
	m_pDataLog->LogHexData((PCHAR)m_pDataLog->bBuffer, (PBYTE)buf, num);
	m_pDataLog->LogString("\n\n");

	return OriginalSend(ssl, buf, num);
}

//BOOL Inline_InstallHook_Recv()
//{
//	ZeroMemory(&RecvHookData, sizeof(HOOK_DATA));
//	strcpy_s(RecvHookData.szApiName, "recv");
//	strcpy_s(RecvHookData.szModuleName, "ws2_32.dll");
//	RecvHookData.HookCodeLen = 15;
//	RecvHookData.HookPoint = (ULONG_PTR)GetAddress(RecvHookData.szModuleName, RecvHookData.szApiName);//HOOK�ĵ�ַ
//																									  //MsgBoxHookData.pfnOriginalFun = (PVOID)OriginalMessageBox;//����ԭʼ������ͨ��
//																									  //x64�²�����������ˣ���������һ���ڴ�����TrampolineFun��shellcode
//	RecvHookData.pfnTrampolineFun = (ULONG_PTR)VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	RecvHookData.pfnDetourFun = (ULONG_PTR)My_Recv;//�Զ���hook����
//	BOOL result = InstallCodeHook(&RecvHookData);
//	OriginalRecv = (PFN_Recv)RecvHookData.pfnTrampolineFun;			//�൱��HOOKǰ��recv����
//	return result;
//}

BOOL Inline_InstallHook_Send()
{
	ZeroMemory(&SendHookData, sizeof(HOOK_DATA));
	strcpy_s(SendHookData.szApiName, "SSL_write");
	strcpy_s(SendHookData.szModuleName, "SGSOL.exe");
	SendHookData.HookCodeLen = 13;
	SendHookData.HookPoint = (ULONG_PTR)GetAddress(SendHookData.szModuleName, SendHookData.szApiName);//HOOK�ĵ�ַ

	sprintf((PCHAR)m_pDataLog->bBuffer, "HookPoint = 0x%llx\n", SendHookData.HookPoint);
	m_pDataLog->LogString((PCHAR)m_pDataLog->bBuffer);

	SendHookData.pfnTrampolineFun = (ULONG_PTR)VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	SendHookData.pfnDetourFun = (ULONG_PTR)My_Send;//�Զ���hook����
	BOOL result = InstallCodeHook(&SendHookData);
	OriginalSend = (PFN_Send)SendHookData.pfnTrampolineFun;			//�൱��HOOKǰ��send����

	m_pDataLog->LogString("\n\n");
	return result;
}

//��ȡָ��ģ����ָ��API�ĵ�ַ
LPVOID GetAddress(char* szModuleName, char *szFuncName)
{
	DWORD dwOffset = 0;

	m_pDataLog->LogString(szFuncName);
	m_pDataLog->LogString("\n");

	if (strcmp(szFuncName, "SSL_write") == 0) {
		dwOffset = 0x14268EAD0 - 0x140000000;
	}
	if (strcmp(szFuncName, "SSL_read") == 0) {
		dwOffset = 0x14268E690 - 0x140000000;
	}

	HMODULE hModule = 0;
	if (hModule = GetModuleHandleA(szModuleName))
	{
		sprintf((PCHAR)m_pDataLog->bBuffer, "BaseAddr = 0x%llx\n", (QWORD)hModule);
		m_pDataLog->LogString((PCHAR)m_pDataLog->bBuffer);

		sprintf((PCHAR)m_pDataLog->bBuffer, "Offset = 0x%llx\n", (QWORD)dwOffset);
		m_pDataLog->LogString((PCHAR)m_pDataLog->bBuffer);
		//MessageBoxA(NULL, (PCHAR)m_pDataLog->bBuffer, "", 0);

		return (LPVOID)((QWORD)hModule + (QWORD)dwOffset);
	}
	else
	{
		m_pDataLog->LogString("GetModuleHandleAʧ��");
	}
}

/*
�����ڵ�ָ��
ʹ�õ���mov rax xxxxx; jmp rax������12
Ϊ�����ָ����м������Ҫ����1��nop
*/
void InitHookEntry(PHOOK_DATA pHookData)
{
	pHookData->newEntry[0] = 0x48;
	pHookData->newEntry[1] = 0xb8;
	*(ULONG_PTR*)(pHookData->newEntry + 2) = (ULONG_PTR)pHookData->pfnDetourFun;
	pHookData->newEntry[10] = 0xff;
	pHookData->newEntry[11] = 0xe0;
	pHookData->newEntry[12] = 0x90;
}


/*
�����hook��ĺ����лص�ԭ�к�����ָ��
��ԭ����������ڵ�ָ�����һ��jmp����
ԭ������ڵ�ָ�
.text:000000014268EAD0 41 56                                   push    r14
.text:000000014268EAD2 56                                      push    rsi
.text:000000014268EAD3 57                                      push    rdi
.text:000000014268EAD4 55                                      push    rbp
.text:000000014268EAD5 53                                      push    rbx
.text:000000014268EAD6 48 83 EC 40                             sub     rsp, 40h
.text:000000014268EADA 44 89 C6                                mov     esi, r8d
*/
VOID InitTrampoline(PHOOK_DATA pHookData)
{
	//����ǰ13�ֽ�
	PBYTE pFun = (PBYTE)pHookData->pfnTrampolineFun;
	memcpy(pFun, (PVOID)pHookData->HookPoint, 13);

	//�ں������һ����תָ��
	pFun += 13;					//����ǰ����ָ��
	pFun[0] = 0xFF;
	pFun[1] = 0x25;
	*(ULONG_PTR*)(pFun + 6) = pHookData->JmpBackAddr;
}


BOOL CheckEntry(PHOOK_DATA pHookData) {
	BOOL bResult = FALSE;

	if (strcmp(pHookData->szApiName, "SSL_write") == 0) {
		m_pDataLog->LogHexData((PCHAR)m_pDataLog->bBuffer, pHookData->oldEntry, 13);

		BYTE Code[13] = { 0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x40,
			0x44, 0x89, 0xC6 };
		for (int i = 0; i < 13; i++) {
			if (pHookData->oldEntry[i] != Code[i]) {
				break;
			}
		}
		bResult = TRUE;
	}

	//if (strcmp(pHookData->szApiName, "SSL_read")) {
	//	;
	//}
	
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
	InitHookEntry(pHookData);						//���Inline Hook����
	InitTrampoline(pHookData);						//����Trampoline
	if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned))	//��ȡ������ԭ����ڵ�ļ���ָ��
	{
		if (CheckEntry(pHookData)) {
			if (WriteProcessMemory(hProcess, OriginalAddr, pHookData->newEntry, pHookData->HookCodeLen, &dwBytesReturned))
			{
				m_pDataLog->LogString("�ɹ�HOOK��");
				bResult = TRUE;
			}
			else {
				m_pDataLog->LogString("WriteProcessMemoryʧ��\n");
			}
		}
		else {
			m_pDataLog->LogString("CheckEntryʧ��\n");
		}
	}
	else {
		m_pDataLog->LogString("ReadProcessMemoryʧ��\n");
	}
	return bResult;
}