#include "Headers.h"

namespace AntiDump
{
	VOID ChangeSizeOfImagine()
	{

		DWORD OldProtect = 0;

		// Get base address of module
		char *pBaseAddr = (char*)GetModuleHandle(NULL);

		// Change memory protection
		VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &OldProtect);

		// Erase the header
		SecureZeroMemory(pBaseAddr, 4096);
	}

	VOID EarsePE()
	{
		PPEB pPeb = (PPEB)__readgsqword(0x60);

		PLDR_DATA_TABLE_ENTRY tableEntry = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);
		tableEntry->DllBase = (PVOID)((INT_PTR)tableEntry->DllBase + 0x100000);
	}
}
