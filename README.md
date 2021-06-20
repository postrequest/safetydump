# safetydump

Rust in-memory MiniDump implementation. 

## Features
- ntdll!NtGetNextProcess to obtain a handle for the desired ProcessId as opposed to [kernel32!OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- Functions dynmaically resolved
- Strings are obfuscated in lib.rs

This was written to integrate with the [link](https://github.com/postrequest/link/) command and control framework for dumping lsass remotely in memory. 

## Acknowledgments
[@m0rv4i](https://github.com/m0rv4i/) for the [MinidumpCallbackRoutine](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nc-minidumpapiset-minidump_callback_routine) implementation in [SafetyDump](https://github.com/m0rv4i/SafetyDump).  
[@TheWover](https://github.com/TheWover) for NtGetNextProcess usage idea. It is also used in [ProcessHacker](https://github.com/processhacker/processhacker).  
