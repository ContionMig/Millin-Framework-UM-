#pragma once
#include "Headers.h"

namespace SystemInfo
{
	float RamSize()
	{
		MEMORYSTATUSEX statex;

		statex.dwLength = sizeof(statex); // I misunderstand that

		GlobalMemoryStatusEx(&statex);

		return (float)statex.ullTotalPhys / (1024 * 1024 * 1024);
	}

	int NumberOfProcessors()
	{
		SYSTEM_INFO info;
		GetSystemInfo(&info);

		return (int)info.dwNumberOfProcessors;
	}

	DWORD GetPageSize()
	{
		SYSTEM_INFO info;
		GetSystemInfo(&info);

		return info.dwPageSize;
	}
}