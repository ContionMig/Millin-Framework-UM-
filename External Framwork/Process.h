#pragma once
#include "Headers.h"

namespace Process
{
	extern HANDLE ProcessHandle(std::string ProcessName);	// creates a handle via name
	extern HANDLE ProcessHandle(DWORD PID);					// creates a handle via pid

	extern DWORD GetProcessID(std::string ProcessName);		// gets pid via process name
	extern std::string GetProcessName(DWORD PID);			// gets the process name via pid

	extern DWORD ParentProcessID(DWORD PID);				// returns the parent pid of program 

	extern CreateProcessS CreateProgram(std::string Path);			// creates program and returns pid

	extern std::vector<DWORD> GetThreadIDs(DWORD PID);

}