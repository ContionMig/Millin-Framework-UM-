#pragma once
#include "Headers.h"

namespace Privilege
{
	extern BOOLEAN RanAsAdmin(); // Check if ran as admin

	extern DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege); // Setting Privileges
}