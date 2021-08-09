// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"

#include<stdlib.h>


VOID HOOK();
VOID UNHOOK();

BOOL Hooked = FALSE;


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
typedef int (WINAPI *PFN_Send)(DWORD *ssl, const void *buf, int num);

//��Ч��HOOKǰ��recv��send�ĺ�����ָ��
//PFN_Recv OriginalRecv = NULL;
PFN_Send OriginalSend = NULL;


//int SSL_write(SSL *ssl, const void *buf, int num)

//����
//int WINAPI My_Recv(SOCKET s, char *buf, int len, int flags);
int WINAPI My_Send(DWORD *ssl, const void *buf, int num);
//BOOL Inline_InstallHook_Recv();
BOOL Inline_InstallHook_Send();
LPVOID GetAddress(char *, char *);
void InitHookEntry(PHOOK_DATA pHookData);
VOID InitTrampoline(PHOOK_DATA pHookData);
BOOL InstallCodeHook(PHOOK_DATA pHookData);

VOID MsgPrint(PBYTE Buffer);



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		HOOK();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		//UNHOOK();
		break;
	}
	return TRUE;
}



VOID HOOK() {
	if (Hooked) {
		return;
	}

	MessageBoxA(0, "װ��HOOK", "HOOK", 0);
	Inline_InstallHook_Send();
	Hooked = TRUE;
}


VOID UNHOOK() {
	MessageBoxA(0, "ж��HOOK", "UNHOOK", 0);
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

int WINAPI My_Send(DWORD *ssl, const void *buf, int num)
{
	/*int ret = OriginalSend(s, buf, len, flags);
	if (ret > 0) {
	if (SendCallBack) {
	SendCallBack(s, buf, ret);
	}
	}
	return ret;*/
	MessageBoxA(NULL, "succ", "", NULL);

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
	strcpy_s(SendHookData.szApiName, "SSL_send");
	strcpy_s(SendHookData.szModuleName, "SGSOL.exe");
	SendHookData.HookCodeLen = 13;
	SendHookData.HookPoint = (ULONG_PTR)GetAddress(SendHookData.szModuleName, SendHookData.szApiName);//HOOK�ĵ�ַ


	MsgPrint((PBYTE)SendHookData.HookPoint);


	SendHookData.pfnTrampolineFun = (ULONG_PTR)VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	SendHookData.pfnDetourFun = (ULONG_PTR)My_Send;//�Զ���hook����
	BOOL result = InstallCodeHook(&SendHookData);
	OriginalSend = (PFN_Send)SendHookData.pfnTrampolineFun;			//�൱��HOOKǰ��send����
	return result;
}

//��ȡָ��ģ����ָ��API�ĵ�ַ
LPVOID GetAddress(char* szModuleName, char *szFuncName)
{
	DWORD dwOffset = 0;
	if (strcmp(szFuncName, "SSL_write")) {
		dwOffset = 0x14268EAD0 - 0x140000000;
	}
	if (strcmp(szFuncName, "SSL_read")) {
		dwOffset = 0x14268E690 - 0x140000000;
	}

	HMODULE hModule = 0;
	if (hModule = GetModuleHandleA(szModuleName))
	{
		//char temp[32];
		//_itoa_s(((long int)hModule) + dwOffset, temp, 32);
		//MessageBoxA(NULL, temp, "", NULL);
		return (LPVOID)(hModule + dwOffset);
	}
	else
	{
		MessageBoxA(NULL, "GetModuleHandleAʧ��", "", NULL);
	}
}

/*
�����ڵ�ָ��
ʹ�õ���mov rax xxxxx; jmp rax������12
Ϊ�����ָ����м������Ҫ����3��nop
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
	pFun += 13; //����ǰ����ָ��
	pFun[0] = 0xFF;
	pFun[1] = 0x25;
	*(ULONG_PTR*)(pFun + 6) = pHookData->JmpBackAddr;
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
	InitHookEntry(pHookData);//���Inline Hook����
	InitTrampoline(pHookData);//����Trampoline
	if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned))	//��ȡ������ԭ����ڵ�ļ���ָ��
	{
		if (WriteProcessMemory(hProcess, OriginalAddr, pHookData->newEntry, pHookData->HookCodeLen, &dwBytesReturned))
		{
			//printf("Install Hook write OK! WrittenCnt=%lld\n", dwBytesReturned);
			bResult = TRUE;
		}
	}
	return bResult;
}






//VOID MsgPrint(PBYTE Buffer) {
//	MessageBoxA(NULL, "asd", "", NULL);
//	CHAR Str[66] = { 0 };
//
//	CHAR Table[] = "0123456789abcdef";
//	for (DWORD i = 0; i < 32; i++) {
//		/*if (((BYTE)(Buffer[i] >> 4)) > 15 || ((Buffer[i]) & 0xf) > 15) {
//			MessageBoxA(NULL, "no", "", NULL);
//		}*/
//		MessageBoxA(NULL, (PCHAR)Table[(Buffer[i] >> 4) & 0xf], "", NULL);
//		MessageBoxA(NULL, (PCHAR)Table[(Buffer[i]) & 0xf], "", NULL);
//		Str[2 * i] = Table[(Buffer[i] >> 4) & 0xf];
//		Str[2 * i + 1] = Table[(Buffer[i]) & 0xf];
//	}
//	Str[64] = '\0';
//	
//	MessageBoxA(NULL, Str, "DEBUG", NULL);
//}


//VOID MsgNum(DWORD) {
//
//}