// execInjector.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

#include "CInjector/CInjector.h"

int _tmain(int argc, _TCHAR* argv[])
{
// 	HWND targetHWnd=::FindWindow(NULL,L"ע���༭��");   
// 	CInjector::injectByRunningSuspend(targetHWnd, TEXT("C:\\dll\\dll.dll"));

	CInjector::injectByCreateSuspend1(TEXT("c:\\windows\\regedit.exe"), TEXT("C:\\dll\\dll.dll"));

	return 0;
}