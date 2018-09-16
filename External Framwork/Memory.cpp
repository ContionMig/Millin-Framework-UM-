#include "Headers.h"
#include <psapi.h>

namespace Memory
{
	int chSizeOfArray(char *chArray)
	{
		for (int iLength = 1; iLength < MAX_PATH; iLength++)
			if (chArray[iLength] == '*')
				return iLength;

		return 0;
	}

	int iSizeOfArray(int *iArray)
	{
		for (int iLength = 1; iLength < MAX_PATH; iLength++)
			if (iArray[iLength] == '*')
				return iLength;

		return 0;
	}

	bool iFind(int *iAry, int iVal)
	{

		for (int i = 0; i < 64; i++)
			if (iVal == iAry[i] && iVal != 0)
				return true;

		return false;
	}

	template <class cReadTem>
	cReadTem ReadVirtualMemory(HANDLE Process, DWORD dwAddress)
	{
		cReadTem cRead;
		ReadProcessMemory(Process, (LPVOID)dwAddress, &cRead, sizeof(cReadTem), NULL);
		return cRead;
	}

	template <class cWriteTem>
	void WriteVirtualMemory(HANDLE Process, DWORD dwAddress, cWriteTem Value)
	{
		WriteProcessMemory(Process, (LPVOID)dwAddress, &Value, sizeof(cWriteTem), NULL);
	}

	DWORD ModuleBaseAddress(LPSTR ModuleName, DWORD PID)
	{
		HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
		MODULEENTRY32 mEntry;
		mEntry.dwSize = sizeof(mEntry);

		do
			if (!strcmp(mEntry.szModule, ModuleName))
			{
				CloseHandle(hModule);
				return (DWORD)mEntry.modBaseAddr;
			}
		while (Module32Next(hModule, &mEntry));

		return 0;
	}

	DWORD AOB_Scan(HANDLE ProcessHandle,DWORD dwAddress, DWORD dwEnd, char *Bytes)
	{
		int iBytesToRead = 0, iTmp = 0;
		int length = chSizeOfArray(Bytes);
		bool bTmp = false;

		if (Bytes[0] == '?')
		{
			for (; iBytesToRead < MAX_PATH; iBytesToRead++)
				if (Bytes[iBytesToRead] != '?')
				{
					iTmp = (iBytesToRead + 1);
					break;
				}
		}

		for (; dwAddress < dwEnd; dwAddress++)
		{
			if (iBytesToRead == length)
				return dwAddress - iBytesToRead;

			if (ReadVirtualMemory<BYTE>(ProcessHandle, dwAddress) == Bytes[iBytesToRead] || (bTmp && Bytes[iBytesToRead] == '?'))
			{
				iBytesToRead++;
				bTmp = true;
			}
			else
			{
				iBytesToRead = iTmp;
				bTmp = false;
			}
		}

		return 0;
	}
	
	DWORD ProgramBaseAddress(HANDLE ProcessHandle)
	{
		return ModuleBaseAddress(const_cast<char *>(Process::GetProcessName(GetProcessId(ProcessHandle)).c_str()), GetProcessId(ProcessHandle));
	}
}