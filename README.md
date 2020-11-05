# ContionMig's Millin FrameWork

[[My Website]](https://mitsuzi.xyz/)

# Features
Process Information:
- Create Process
- Process Name via PID
- Process Handle via Name and PID
- Getting Process Threads

Anti Debug ( [Credits](https://github.com/mrexodia/TitanHide) ):
- CheckRemoteDebuggerPresent
- IsDebuggerPresent
- NtGlobalFlag
- ProcessDebugFlags (NtQueryInformationProcess)
- ProcessDebugPort (NtQueryInformationProcess)
- ProcessDebugObjectHandle (NtQueryInformationProcess)
- DebugObject (NtQueryObject)
- SystemKernelDebuggerInformation (NtQuerySystemInformation)
- SystemDebugControl (NtSystemDebugControl)
- NtClose (STATUS_INVALID_HANDLE exception)
- ThreadHideFromDebugger (NtSetInformationThread)

Anti Dump ( [Credits](https://github.com/LordNoteworthy/al-khaser) ):
- Earsing PE Headers
- Increasing Image Size

Anti VM:
- Checking Loaded DLLs
- Checking Registers
- Checking Services
- Checking Running Windows
- Checking Processes

Injection:
- Standard Remote Thread
- Standard APC Inection 
- Standard SetWindowsHook Injection
- Manual Mapper

Memory:
- Read Process Virtual Memory
- Write Process Virtual Memory
- AOB Scans
- Retriving Module Base Address
- Retriving Program Base Address

Privilege:
- Check If Program Is Ran As Admin
- Adjusting Token Privileges

System Info:
- Physical Memory Size
- Number Of Processors
- Page Size

Maths:
- Vectors
- Matrixes
- Simple Square Root

Xor ( [Credit](https://github.com/KN4CK3R/XorStr ))

# TO-DO
- Adding More Injection Methods
- Adding More Anti Dump Methods
- Adding Functions Which Enumerate Drivers And Other Running Softwares

# Notes
I will be working on this framework along the days, adding things and improving the overall source. At this point, my goal is to add more features and try to complete the TO DO list. 

 
# System Portability 
- Only Tested On Windows 7 x64

![alt text](https://i.imgur.com/jdJsDJh.png)

# Credits
https://github.com/mrexodia/TitanHide ( https://github.com/mrexodia/TitanHide/blob/master/LICENSE )
https://github.com/LordNoteworthy/al-khaser ( https://github.com/LordNoteworthy/al-khaser/blob/master/LICENSE )
https://github.com/KN4CK3R/XorStr
https://github.com/ItsJustMeChris/Manual-Mapper
https://github.com/Sleevelesss/CS-GO-Simple-External
