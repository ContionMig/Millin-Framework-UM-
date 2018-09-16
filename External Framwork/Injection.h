#pragma once
#include "Headers.h"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

namespace Inject
{
	extern DWORD RemoteThread(PCWSTR FilePath, HANDLE ProcessHandle);	// CreateRemoteThread Injection Using HANDLE

	extern DWORD APCinjection(TCHAR *dll_name, HANDLE ProcessHandle); // Injection by queuing a APC using QueueUserAPC

	extern DWORD SetWindowsHookInjection(LPCTSTR  FilePath, LPCTSTR ProcessName, LPCSTR FunctionName); // Injecting using SetWindowsHook

	//github.com/ItsJustMeChris/Manual-Mapper/blob/master/Heroin/needle.h Credits
	extern void __stdcall Shellcode(MANUAL_MAPPING_DATA * pData);
	extern DWORD ManualMap(HANDLE hProc, const char * szDllFile); // Standard Manual Mapper
}