#include "Headers.h"

namespace Privilege
{
	BOOLEAN RanAsAdmin()
	{
		BOOL fRet = FALSE;
		HANDLE hToken = NULL;
		if (OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken))
		{
			TOKEN_ELEVATION Elevation;
			DWORD cbSize = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
			{
				fRet = Elevation.TokenIsElevated;
			}
		}
		if (hToken)
		{
			CloseHandle(hToken);
		}
		return fRet;
	}

	DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
	{
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
		{
			return 1;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (bEnablePrivilege)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		// Enable the privilege or disable all privileges.

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		{
			return 2;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			return 3;
		}

		return 0;
	}
}