// RemoteInjectDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

#include "winuser.h "

void test() {
	MessageBoxA(0, "Hello", "Hello", 0);
}