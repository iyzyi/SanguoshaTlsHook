// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"


VOID HOOK();
VOID UNHOOK();

BOOL Hooked = FALSE;


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
	if (!Hooked) {
		MessageBoxA(0, "װ��HOOK", "HOOK", 0);
		Hooked = TRUE;
	}
}


VOID UNHOOK() {
	MessageBoxA(0, "ж��HOOK", "UNHOOK", 0);
}