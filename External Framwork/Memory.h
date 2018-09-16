#pragma once
#include "Headers.h"

namespace Memory
{
	extern int chSizeOfArray(char *chArray);
	extern int iSizeOfArray(int *iArray);
	extern bool iFind(int *iAry, int iVal);

	template <class cReadTem>
	extern cReadTem ReadVirtualMemory(HANDLE Process, DWORD dwAddress);

	template <class cWriteTem>
	extern void WriteVirtualMemory(HANDLE Process, DWORD dwAddress, cWriteTem Value);
	
	extern DWORD AOB_Scan(HANDLE ProcessHandle, DWORD dwAddress, DWORD dwEnd, char *Bytes);

	extern DWORD ModuleBaseAddress(LPSTR ModuleName, DWORD PID);

	extern DWORD ProgramBaseAddress(HANDLE ProcessHandle);
}