# Overview
This script uses the Hell's Gate technique along with AES encrypted shellcode/API names to inject the shellcode into a given remote process.  **All of the code needed to do this should be embedded in the generate-implant.py script (apart from the system requirements)**, but the source files are provided in this repository for reference.

Nearly all of the base code is taken from the posts below so I could see how Hell's Gate was implemented and mess around with it.  The compile script and encryption/obfuscation techniques are from the Red Team Operator courses provided at https://institute.sektor7.net/.

- https://teamhydra.blog/2020/09/18/implementing-direct-syscalls-using-hells-gate/
- https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time

The basic explanation for the Hell's Gate technique is that, rather than using the well-known Win API functions that are commonly hooked in userland, you can instead dynamically find the direct syscalls on the host by parsing ntdll.dll and calling them in a custom implementation.

This application's flow uses the syscalls below.

1.  **NtOpenProcess** to get a handle on the target process
2.  **NtAllocateVirtualMemory** to allocate memory in the target process for the payload
3.  **NtWriteVirtualMemory** to copy payload into allocated memory
4.  **NtProtectVirtualMemory** to make allocated memory executable
5.  **NtCreateThreadEx** to execute code in allocated memory

# Requirements
- Windows Machine
- Python3 with pycryptodome library (provided in requirements.txt)
- Visual Studio Command Line Tools


# Usage
The command below should be run in a folder by itself (to keep things organized) with a shellcode file provided as an argument.

```default
python generate-implant.py C:\Payloads\cs.bin
```

It will generate a new folder named "src" and write the following files to it from the Base64 versions embedded in the script.

- compile.bat
- helpers.cpp
- helpers.h
- PEstructs.h
- structs.h
- implant.cpp

When the compilation process is complete, is should generate a new executable named "implant.exe" in the same folder as the Python script.

This implant is used by simply running it on the command line and providing the PID of a target process to inject the shellcode into.  In the example below, a notepad.exe process was launched ahead of time with the PID 15324.

```default
C:\Tools\RTO-Malware\test>implant.exe 15324
Opening target process with PID 15324
Allocating 896 bytes
Writing shellcode to 0x00000290B4550000
Changing memory permissions
Creating remote thread
Success!
```