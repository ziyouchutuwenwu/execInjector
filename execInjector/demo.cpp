// execInjector.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include "CInjector/CInjector.h"

int _tmain(int argc, _TCHAR* argv[])
{
// 	HWND targetHWnd=::FindWindow(NULL,L"注册表编辑器");   
// 	CInjector::injectByRunningSuspend(targetHWnd, TEXT("C:\\dll\\dll.dll"));

	CInjector::injectByCreateSuspend1(TEXT("c:\\windows\\regedit.exe"), TEXT("C:\\dll\\dll.dll"));

	return 0;
}