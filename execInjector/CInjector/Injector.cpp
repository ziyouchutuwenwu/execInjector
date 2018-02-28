#include "StdAfx.h"

#include "Injector.h"

bool CInjector::injectByRunningSuspend(HWND targetHWnd, WCHAR pDllPath[]){  

	DWORD pid,tid;  
	tid = GetWindowThreadProcessId(targetHWnd,&pid);  
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);  
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,tid);  
	if( hThread <= 0 ) return false;

	SuspendThread(hThread);

	CONTEXT threadContext ={0};  
	threadContext.ContextFlags = CONTEXT_CONTROL;  
	GetThreadContext(hThread, &threadContext);

	DWORD dwSize = sizeof(WCHAR)*1024;//分配出空间给shellcode
	BYTE* pShellcode = (BYTE*)::VirtualAllocEx(hProcess,NULL,dwSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);

	BYTE* pAllocedDllPath = pShellcode + 0x100;

	DWORD dwWrited = 0;
	::WriteProcessMemory(hProcess, pAllocedDllPath, pDllPath,(wcslen(pDllPath) + 1) * sizeof(WCHAR), &dwWrited);

	FARPROC pLoadLibraryW = (FARPROC)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "LoadLibraryW");

	BYTE shellcode[32] = { 0 };

	DWORD* pdllPath = NULL;
	DWORD* pLoadLibraryRVA = NULL;
	DWORD* pOldEipRVA = NULL;

	shellcode[0] = 0x60;																	// pushad
	shellcode[1] = 0x9C;																	// pushfd

	shellcode[2] = 0x68;																	// push
	pdllPath = (DWORD *)&shellcode[3];														// ShellCode[3/4/5/6]
	*pdllPath = (DWORD)(pAllocedDllPath);

	shellcode[7] = 0xE8;																	// call  
	pLoadLibraryRVA = (DWORD *)&shellcode[8];												// ShellCode[8/9/10/11]  
	*pLoadLibraryRVA = (DWORD)pLoadLibraryW - ((DWORD)(pShellcode + 7) + 5 );				// 因为直接call地址了，所以对应机器码需要转换，计算VA


	shellcode[12] = 0x9D;																	// popfd  
	shellcode[13] = 0x61;																	// popad  

	shellcode[14] = 0xE9;																	// jmp 
	pOldEipRVA = (DWORD *)&shellcode[15];													// ShellCode[15/16/17/18]

	*pOldEipRVA = threadContext.Eip - ((DWORD)(pShellcode + 14) + 5);						//因为直接jmp地址了，所以对应机器码需要转换，计算VA
	::WriteProcessMemory(hProcess, pShellcode, shellcode, sizeof(shellcode), &dwWrited);

	threadContext.Eip = (DWORD)pShellcode;
	::SetThreadContext(hThread, &threadContext);
	::ResumeThread(hThread);
	::CloseHandle(hProcess);
	::CloseHandle(hThread);

	return true;
}

bool CInjector::injectByCreateSuspend1(TCHAR exeFullPath[], TCHAR szDll[]){
	bool isSuccess = false;

	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	TCHAR szCommandLine[MAX_PATH];
	_tcscpy(szCommandLine, exeFullPath);

	::CreateProcess(NULL, szCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);    
	LPVOID Param = VirtualAllocEx(pi.hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);    
	WriteProcessMemory(pi.hProcess, Param, (LPVOID)szDll, _tcslen(szDll)*2+sizeof(TCHAR), NULL);    

	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryW,Param, CREATE_SUSPENDED, NULL);    
	ResumeThread(pi.hThread);

	if (hThread){    
		ResumeThread(hThread);    
		WaitForSingleObject(hThread, INFINITE);

		isSuccess = true;
	}

	return isSuccess;
}

bool CInjector::injectByCreateSuspend2(TCHAR exeFullPath[], TCHAR szDll[]){
	bool isSuccess = false;

	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	TCHAR szCommandLine[MAX_PATH];
	_tcscpy(szCommandLine, exeFullPath);

	TCHAR pDllPath[MAX_PATH];
	_tcscpy(pDllPath, szDll);

	::CreateProcess(NULL, szCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);    
	LPVOID Param = VirtualAllocEx(pi.hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);    
	WriteProcessMemory(pi.hProcess, Param, (LPVOID)szDll, _tcslen(szDll)*2+sizeof(TCHAR), NULL);    

	CONTEXT threadContext ={0};  
	threadContext.ContextFlags = CONTEXT_CONTROL;  
	GetThreadContext(pi.hThread, &threadContext);

	BYTE* pShellcode = (BYTE*)Param;
	BYTE* pAllocedDllPath = pShellcode + 0x100;

	DWORD dwWrited = 0;
	::WriteProcessMemory(pi.hProcess, pAllocedDllPath, pDllPath,(wcslen(pDllPath) + 1) * sizeof(WCHAR), &dwWrited);

	FARPROC pLoadLibraryW = (FARPROC)::GetProcAddress(::GetModuleHandle(L"Kernel32"), "LoadLibraryW");

	BYTE shellcode[32] = { 0 };

	DWORD* pdllPath = NULL;
	DWORD* pLoadLibraryRVA = NULL;
	DWORD* pOldEipRVA = NULL;

	shellcode[0] = 0x60;																	// pushad
	shellcode[1] = 0x9C;																	// pushfd

	shellcode[2] = 0x68;																	// push
	pdllPath = (DWORD *)&shellcode[3];														// ShellCode[3/4/5/6]
	*pdllPath = (DWORD)(pAllocedDllPath);

	shellcode[7] = 0xE8;																	// call  
	pLoadLibraryRVA = (DWORD *)&shellcode[8];												// ShellCode[8/9/10/11]  
	*pLoadLibraryRVA = (DWORD)pLoadLibraryW - ((DWORD)(pShellcode + 7) + 5 );				// 因为直接call地址了，所以对应机器码需要转换，计算VA


	shellcode[12] = 0x9D;																	// popfd  
	shellcode[13] = 0x61;																	// popad  

	shellcode[14] = 0xE9;																	// jmp 
	pOldEipRVA = (DWORD *)&shellcode[15];													// ShellCode[15/16/17/18]

	*pOldEipRVA = threadContext.Eip - ((DWORD)(pShellcode + 14) + 5);						//因为直接jmp地址了，所以对应机器码需要转换，计算VA
	::WriteProcessMemory(pi.hProcess, pShellcode, shellcode, sizeof(shellcode), &dwWrited);

	threadContext.Eip = (DWORD)pShellcode;
	::SetThreadContext(pi.hThread, &threadContext);
	::ResumeThread(pi.hThread);
	::CloseHandle(pi.hProcess);
	::CloseHandle(pi.hThread);

	ResumeThread(pi.hThread);    
	WaitForSingleObject(pi.hThread, INFINITE);

	isSuccess = true;

	return isSuccess;
}

CInjector::CInjector(void)
{

}


CInjector::~CInjector(void)
{
}
