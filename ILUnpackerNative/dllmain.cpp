#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>

#ifndef _WIN64
DWORD From;
DWORD To;
#else
DWORD64 From;
DWORD64 To;
#endif

LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
#ifndef _WIN64
	if ((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == From)
#else
	if ((DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress == From)
#endif
	{
		GetCurrentThreadId();
#ifndef _WIN64
		ExceptionInfo->ContextRecord->Eip = To;
#else
		ExceptionInfo->ContextRecord->Rip = To;
#endif
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

#ifndef _WIN64
extern "C" __declspec(dllexport) void __stdcall ILUnpacker_SetHook86(DWORD from, DWORD to)
#else
extern "C" __declspec(dllexport) void __fastcall ILUnpacker_SetHook64(DWORD64 from, DWORD64 to)
#endif
{
	AddVectoredExceptionHandler(TRUE, (LPTOP_LEVEL_EXCEPTION_FILTER)ExceptionFilter);

	From = from;
	To = to;

	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == GetCurrentProcessId())
					{
						HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
						CONTEXT context;
						context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
						if (GetThreadContext(thread, &context))
						{
							context.Dr0 = From;
							context.Dr7 = 0x00000001;
						}
						SetThreadContext(thread, &context);
						CloseHandle(thread);
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}