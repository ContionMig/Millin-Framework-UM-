// External Framwork.cpp : Defines the entry point for the console application.
//

#include "Headers.h"

HANDLE hToken = NULL;

int main()
{
	printf("==========          Made By: Sagaan             ==========\n");
	printf("==========          Millin FrameWork            ==========\n");
	printf("==========        Process information           ==========\n");
	CreateProcessS StartUpCal = Process::CreateProgram("C:\\Windows\\system32\\calc.exe");
	printf("Created Process ID:			%d \n", StartUpCal.PID);
	printf("Created Process Name:			%s \n", Process::GetProcessName(StartUpCal.PID));
	printf("Created Process Handle:			0x%p \n", StartUpCal.hProcess);
	printf("\n");
	printf("ProcessHandle Chrome:			0x%p \n", Process::ProcessHandle("chrome.exe"));
	printf("Process Name:				%s \n", Process::GetProcessName(Process::GetProcessID("chrome.exe")));
	printf("Parent Process ID:			%d \n", Process::ParentProcessID(Process::GetProcessID("chrome.exe")));
	printf("Parent Process Name:			%s \n", Process::GetProcessName(Process::ParentProcessID(Process::GetProcessID("chrome.exe"))));
	printf("\n");



	printf("==========        Privilege information         ==========\n");
	OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	printf("Program Ran As Admin:			%s \n" , Privilege::RanAsAdmin() ? "TRUE" : "FALSE");
	printf("Set Debug Privilege:			%s \n", Privilege::SetPrivilege(hToken, SE_DEBUG_NAME, TRUE) ? "FALSE" : "TRUE");
	printf("\n");



	printf("==========        Injection information         ==========\n");
	printf("RemoteThread Injection:			%s \n", Inject::RemoteThread(L"DLL Test.dll", Process::ProcessHandle("calc.exe")) ? "FALSE" : "TRUE");
	printf("APC Injection:				%s \n",	Inject::APCinjection("DLL Test.dll", Process::ProcessHandle("calc.exe")) ? "FALSE" : "TRUE");
	printf("SetWindowsHook Injection:		%s \n", Inject::SetWindowsHookInjection("DLL Test.dll", "calc.exe", "CallingMessagebox") ? "FALSE" : "TRUE");
	printf("Manual Map Injection:			%s \n", Inject::ManualMap(Process::ProcessHandle("calc.exe"), "DLL Test.dll") ? "FALSE" : "TRUE");
	printf("\n");



	printf("==========        Anti-Debug information       ==========\n");
	printf("DebuggerPresent:			%s\n", AntiDebug::DebuggerPresent() ? "TRUE" : "FALSE");
	printf("CheckNtGlobalFlag:			%s\n", AntiDebug::CheckNtGlobalFlag() ? "TRUE" : "FALSE");
	printf("ProcessDebugFlags:			%s\n", AntiDebug::CheckProcessDebugFlags() ? "TRUE" : "FALSE");
	printf("ProcessDebugPort:			%s\n", AntiDebug::CheckProcessDebugPort() ? "TRUE" : "FALSE");
	printf("ProcessDebugObjectHandle:		%s\n", AntiDebug::CheckProcessDebugObjectHandle() ? "TRUE" : "FALSE");
	printf("NtQueryObject:				%s\n", AntiDebug::CheckObjectList() ? "TRUE" : "FALSE");
	printf("CheckSystemDebugger:			%s\n", AntiDebug::CheckSystemDebugger() ? "TRUE" : "FALSE");
	printf("SystemDebugControl:			%s\n", AntiDebug::CheckSystemDebugControl() ? "TRUE" : "FALSE");
	printf("CheckNtClose:				%s\n", AntiDebug::CheckNtClose() ? "TRUE" : "FALSE");
	printf("Check Devices:				%s\n", AntiDebug::CheckDevices() ? "TRUE" : "FALSE");
	printf("Check Process:				%s\n", AntiDebug::CheckProcess() ? "TRUE" : "FALSE");
	printf("\n");



	printf("==========        Anti-VM information         ==========\n");
	printf("Check DLL:				%s\n", AntiVM::CheckLoadedDLLs() ? "TRUE" : "FALSE");
	printf("Check Reg Key:				%s\n", AntiVM::CheckRegKeys() ? "TRUE" : "FALSE");
	printf("Check Devices:				%s\n", AntiVM::CheckDevices() ? "TRUE" : "FALSE");
	printf("Check Windows:				%s\n", AntiVM::CheckWindows() ? "TRUE" : "FALSE");
	printf("Check Process:				%s\n", AntiVM::CheckProcess() ? "TRUE" : "FALSE");
	printf("\n");



	printf("==========        Anti-Dump information       ==========\n");

	AntiDump::ChangeSizeOfImagine();
	AntiDump::EarsePE();

	printf("Erased PE Header.... \n");
	printf("Increased Size Of Image.... \n");

	printf("\n");



	printf("==========        System information         ==========\n");
	printf("Physical Ram: %d GB \n", (int)SystemInfo::RamSize());
	printf("Number Of Processors: %d \n", (int)SystemInfo::NumberOfProcessors());
	printf("Physical Memory Page Size: %d KB\n", SystemInfo::GetPageSize());
	printf("\n");



	printf("==========               XOR                 ==========\n");
	std::cout << _xor_("XOR Test 1").c_str() << '\n';

	auto test = _xor_("XOR Test 2");
	std::cout << test.c_str() << '\n';

	std::string s2 = _xor_("XOR Test 3");
	std::cout << s2 << '\n';

	printf("\n");



	printf("==========              Memory               ==========\n");
	printf("Process Base Address: 0x%X \n", Memory::ProgramBaseAddress(StartUpCal.hProcess));
	printf("Process Module Base Address (ntdll.dll): 0x%X \n", Memory::ModuleBaseAddress("ntdll.dll",StartUpCal.PID));
	printf("\n");
	system("pause");
    return 0;
}

