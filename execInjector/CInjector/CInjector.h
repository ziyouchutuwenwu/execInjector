#pragma once

#include <windows.h>

class CInjector
{
public:
	static bool CInjector::injectByRunningSuspend(HWND targetHWnd, WCHAR pDllPath[]);
	static bool CInjector::injectByCreateSuspend1(TCHAR exeFullPath[], TCHAR szDll[]);
	static bool CInjector::injectByCreateSuspend2(TCHAR exeFullPath[], TCHAR szDll[]);

private:
	CInjector(void);
	~CInjector(void);
};