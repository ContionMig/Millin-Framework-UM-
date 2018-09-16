#include "Headers.h"

namespace Process
{
	HANDLE ProcessHandle(std::string ProcessName)
	{
		DWORD pid = 0;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);

		if (Process32First(snapshot, &process))
		{
			do
			{
				if ((std::string)process.szExeFile == (std::string)ProcessName)
				{
					CloseHandle(snapshot);
					return OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.th32ProcessID);
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);
		return NULL;
	}

	HANDLE ProcessHandle(DWORD PID)
	{
		return OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	}

	DWORD GetProcessID(std::string ProcessName)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);

		if (Process32First(snapshot, &process))
		{
			do
			{
				if ((std::string)process.szExeFile == (std::string)ProcessName)
				{
					CloseHandle(snapshot);
					return process.th32ProcessID;
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);
		return NULL;
	}

	std::string GetProcessName(DWORD PID)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);

		if (Process32First(snapshot, &process))
		{
			do
			{
				if (process.th32ProcessID == PID)
				{
					CloseHandle(snapshot);
					return process.szExeFile;
				}
			} while (Process32Next(snapshot, &process));
		}
		CloseHandle(snapshot);
		return NULL;
	}

	DWORD ParentProcessID(DWORD PID)
	{
		HANDLE hSnapshot;
		PROCESSENTRY32 pe32;

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) return 0;
		do {
			if (pe32.th32ProcessID == PID)
			{
				CloseHandle(hSnapshot);
				return pe32.th32ParentProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
		CloseHandle(hSnapshot);
		return 0;
	}

	CreateProcessS CreateProgram(std::string Path)
	{
		CreateProcessS Information;
		STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
		PROCESS_INFORMATION ProcessInfo;
		if (CreateProcessA(Path.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
		{
			Information.PID = ProcessInfo.dwProcessId;
			Information.hProcess = ProcessInfo.hProcess;
			return Information;
		}
	}

	std::vector<DWORD> GetThreadIDs(DWORD PID)
	{
		std::vector<DWORD> tids;
		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			return { 0 };

		PROCESSENTRY32 pe = { sizeof(pe) };
		if (::Process32First(hSnapshot, &pe)) 
		{
			do 
			{
				if (pe.th32ProcessID == PID)
				{
					THREADENTRY32 te = { sizeof(te) };
					if (Thread32First(hSnapshot, &te)) 
					{
						do {
							if (te.th32OwnerProcessID == PID)
							{
								tids.push_back(te.th32ThreadID);
							}
						} while (Thread32Next(hSnapshot, &te));
					}
					break;
				}
			} while (Process32Next(hSnapshot, &pe));
		}

		CloseHandle(hSnapshot);
		return tids;
	}
}