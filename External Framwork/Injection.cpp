#include "Headers.h"

namespace Inject
{
	DWORD RemoteThread(PCWSTR FilePath, HANDLE ProcessHandle)
	{
		DWORD dwSize = (lstrlenW(FilePath) + 1) * sizeof(wchar_t);

		if (ProcessHandle == NULL)
		{
			return 1;
		}

		LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(ProcessHandle, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL)
		{
			return 2;
		}

		DWORD n = WriteProcessMemory(ProcessHandle, pszLibFileRemote, (PVOID)FilePath, dwSize, NULL);
		if (n == 0)
		{
			return 3;
		}

		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL)
		{
			return 4;
		}

		HANDLE hThread = CreateRemoteThread(ProcessHandle, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
		if (hThread == NULL)
		{
			return 5;
		}
		else
		{
			return 0;
		}
		WaitForSingleObject(hThread, INFINITE);

		if (pszLibFileRemote != NULL)
			VirtualFreeEx(ProcessHandle, pszLibFileRemote, 0, MEM_RELEASE);

		if (hThread != NULL)
			CloseHandle(hThread);
	}

	DWORD APCinjection(TCHAR *dll_name, HANDLE ProcessHandle)
	{
		TCHAR lpdllpath[MAX_PATH];
		GetFullPathName(dll_name, MAX_PATH, lpdllpath, nullptr);

		DWORD pid{};
		std::vector<DWORD> tids = Process::GetThreadIDs(GetProcessId(ProcessHandle));

		if (!ProcessHandle)
		{
			return 1;
		}

		auto pVa = VirtualAllocEx(ProcessHandle, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!WriteProcessMemory(ProcessHandle, pVa, lpdllpath, sizeof(lpdllpath), nullptr))
		{
			return 2;
		}

		for (const auto &tid : tids) {
			auto hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
			if (hThread)
			{
				QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryW"), hThread, (ULONG_PTR)pVa);
				CloseHandle(hThread);
			}
		}
		return 0;
	}

	DWORD SetWindowsHookInjection(LPCTSTR  FilePath, LPCTSTR ProcessName, LPCSTR FunctionName)
	{
		HMODULE dll = LoadLibrary(FilePath);
		if (dll == NULL) {
			return 1;
		}

		HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, FunctionName);

		unsigned long procID;
		HWND targetWnd = FindWindow(NULL, ProcessName);
		GetWindowThreadProcessId(targetWnd, &procID);

		HHOOK handle = SetWindowsHookEx(WH_CBT, addr, dll, 0);

		return 0;
	}

	// https://github.com/ItsJustMeChris/Manual-Mapper/blob/master/Heroin/needle.cpp
	void __stdcall Shellcode(MANUAL_MAPPING_DATA * pData)
	{
		if (!pData)
			return;
		//Process base
		BYTE * pBase = reinterpret_cast<BYTE*>(pData);
		//Optional data
		auto * pOptionalHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

		auto _LoadLibraryA = pData->pLoadLibraryA;
		auto _GetProcAddress = pData->pGetProcAddress;
		auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOptionalHeader->AddressOfEntryPoint);

		BYTE * LocationDelta = pBase - pOptionalHeader->ImageBase;
		if (LocationDelta)
		{
			if (!pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
				return;

			auto * pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress)
			{
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD * pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
				{
					if (RELOC_FLAG(*pRelativeInfo))
					{
						UINT_PTR * pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}

		if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			auto * pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescr->Name)
			{
				char * szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
				HINSTANCE hDll = _LoadLibraryA(szMod);

				ULONG_PTR * pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
				ULONG_PTR * pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

				if (!pThunkRef)
					pThunkRef = pFuncRef;

				for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
				{
					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
					{
						*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
					}
					else
					{
						auto * pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
						*pFuncRef = _GetProcAddress(hDll, pImport->Name);
					}
				}
				++pImportDescr;
			}
		}

		if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			auto * pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto * pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			for (; pCallback && *pCallback; ++pCallback)
				(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
		//Execute dll main
		_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
	}
	DWORD ManualMap(HANDLE hProc, const char * szDllFile)
	{
		BYTE *					pSourceData = nullptr;
		IMAGE_NT_HEADERS *		pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER * pOldOptionalHeader = nullptr;
		IMAGE_FILE_HEADER *		pOldFileHeader = nullptr;
		BYTE *					pTargetBase = nullptr;

		//Check if the file exists
		if (!GetFileAttributesA(szDllFile))
		{
			return 1;
		}

		//Get the files data as binary
		std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

		//Check if we can open the file
		if (File.fail())
		{
			File.close();
			return 2;
		}

		//We are at the end of the file, so we know the size already.  
		auto FileSize = File.tellg();
		//Let's get the byte array of the file.  
		pSourceData = new BYTE[static_cast<UINT_PTR>(FileSize)];
		//If we couldn't allocate memory for this data we failed
		if (!pSourceData)
		{
			File.close();
			return 3;
		}
		//Back to the start of the file.  
		File.seekg(0, std::ios::beg);
		//Read the entire file
		File.read(reinterpret_cast<char*>(pSourceData), FileSize);
		//We don't need the file anymore. 
		File.close();
		//Check if it's a valid PE file
		if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_magic != 0x5A4D)
		{
			delete[] pSourceData;
			return 4;
		}
		//Save the old NT Header
		pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_lfanew);
		//Save the old optional header
		pOldOptionalHeader = &pOldNtHeader->OptionalHeader;
		//Save the old file header
		pOldFileHeader = &pOldNtHeader->FileHeader;
		//Handle X86 and X64
#ifdef _WIN64
		//If the machine type is not the current file type we fail
		if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
		{
			printf("Invalid platform\n");
			delete[] pSourceData;
			return 5;
		}
#else
		//If the machine type is not the current file type we fail
		if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
		{
			printf("Invalid platform\n");
			delete[] pSourceData;
			return 5;
		}
#endif
		//Get the target base address to allocate memory in the target process
		//Try to load at image base of the old optional header, the size of the optional header image, commit = make , reserve it, execute read write to write the memory
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptionalHeader->ImageBase), pOldOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			//We can't allocate it, lets initialize it instead?
			//Forget the image base, just use nullptr, if this fails we cannot allocate memory in the target process.  
			pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
			if (!pTargetBase)
			{
				//We couldn't allocate memory.  
				printf("Memory allocation failed 0x%X\n", GetLastError());
				//Cleanup
				delete[] pSourceData;
				//Fail
				return 6;
			}
		}
		//Declare data to map
		MANUAL_MAPPING_DATA data{ 0 };
		//Declare function prototype
		data.pLoadLibraryA = LoadLibraryA;
		//Declare function prototype
		data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

		//Get the section header
		auto * pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		//Loop the file header sections for section data, we only care about the raw data in here, it contains other data that is used after runtime which we dont care about.  
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		{
			//If it's raw data
			if (pSectionHeader->SizeOfRawData)
			{
				//Try to write our source data into the process, mapping.
				if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSourceData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
				{
					//We couldn't allocate memory 
					printf("Failed to allocate memory: 0x%x\n", GetLastError());
					delete[] pSourceData;
					VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
					return 7;
				}
			}
		}
		//Copy our source data and our new data
		memcpy(pSourceData, &data, sizeof(data));
		WriteProcessMemory(hProc, pTargetBase, pSourceData, 0x1000, nullptr);
		//Cleanup 
		delete[] pSourceData;

		void * pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode)
		{
			printf("Memory allocation failed (1) (ex) 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			return 8;
		}

		WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr);

		HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
		if (!hThread)
		{
			printf("Thread creation failed 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return 9;
		}

		CloseHandle(hThread);

		HINSTANCE hCheck = NULL;
		while (!hCheck)
		{
			MANUAL_MAPPING_DATA data_checked{ 0 };
			ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
			hCheck = data_checked.hMod;
			Sleep(10);
		}

		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

		return 0;
	}


}
