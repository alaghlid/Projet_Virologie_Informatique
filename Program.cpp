// Program.cpp : définit le point d'entrée pour l'application console.


/*	Projet de Virologie Informatique 
 *    LAGHLID Ayoub - ZKIM Youssef
 *			5ASL - 2022/2023
*/

#include "Stdafx.h"
#include <stdio.h>
#include <Windows.h>

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <excpt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include<iostream>
using namespace std;
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "psapi.lib")

int key=190898;

BOOL debuggerPresent()
{
	return IsDebuggerPresent();
}

DWORD beeingDebugged()
{
	__asm
	{
		mov eax, fs:[0x30]				
			movzx eax, byte ptr[eax + 2]		
	}
}

//CheckRemoteDebuggerPresent
BOOL CheckRemoteDebuggerPresent()
{
	BOOL result;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);
	return result;
}

//CloseHandle
/*
APIs making user of the ZwClose syscall (such as CloseHandle, indirectly)
can be used to detect a debugger. When a process is debugged, calling ZwClose
with an invalid handle will generate a STATUS_INVALID_HANDLE (0xC0000008) exception.
As with all anti-debugs that rely on information made directly available.
*/


BOOL NtClose_InvalideHandle()
{
	// Function Pointer Typedef for NtClose
	typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);

	// We have to import the function
	pNtClose NtClose_ = NULL;

	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}

	NtClose_ = (pNtClose)GetProcAddress(hNtdll, "NtClose");
	if (NtClose_ == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	__try {
		// Time to finally make the call
		NtClose_((HANDLE)0x99999999);
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;

}

BOOL CloseHandle_InvalideHandle()
{
	// Let's try first with user mode API: CloseHandle
	__try {
		CloseHandle((HANDLE)0x99999999);
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	// Direct call to NtClose to bypass user mode hooks
	if (NtClose_InvalideHandle())
		return TRUE;
	else
		return FALSE;
}

//find window
BOOL findWindow()
{
	BOOL result = FALSE;
	if (FindWindow(L"OLLYDBG", 0) || FindWindow(L"WinDbgFrameClass", 0))
		result = TRUE;
	return result;
}


//system time difference 
BOOL sysTimeDiff(SYSTEMTIME s_time1, FILETIME f_time1)
{
	SYSTEMTIME s_time2;
	FILETIME f_time2;
	GetSystemTime(&s_time2);
	SystemTimeToFileTime(&s_time2, &f_time2);
	if ((f_time2.dwLowDateTime - f_time1.dwLowDateTime) / 10000 > 1000) {
		return 1;
	}
	return 0;
}

//tick count ( time from when pc was last turned on
BOOL tickCount(DWORD count1)
{
	DWORD count2;
	count2 = GetTickCount();
	if ((count2 - count1) > 0x10) {
		return 1;
	}
	return 0;
}

//Hardware_BreakPoint_GetThreadContext.cpp
BOOL hardwareBreakPoint_ThreadContext()
{
	BOOL result = FALSE;

	CONTEXT ct;
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	GetThreadContext(GetCurrentThread(), &ct);

	if (ct.Dr0 || ct.Dr1 || ct.Dr2 || ct.Dr3)
		result = TRUE;
	return result;
}


// hardwareBreakPoint_SEH
BOOL anti_debug_flag_seh = FALSE;
EXCEPTION_DISPOSITION __cdecl _except_handler(
	__in struct _EXCEPTION_RECORD 	* _ExceptionRecord,
	__in void 					* _EstablisherFrame,
	__inout struct _CONTEXT 			* _ContextRecord,
	__inout void 					* _DispatcherContext
	)
{
	_ContextRecord->Ecx = 1;

	if (_ContextRecord->Dr0 || _ContextRecord->Dr1 || _ContextRecord->Dr2 || _ContextRecord->Dr3)
		anti_debug_flag_seh = TRUE;
	return ExceptionContinueExecution;
}

void hardwareBreakPoint_SEH()
{
	ULONG seh_handler = (ULONG)_except_handler;

	__asm
	{
		push	seh_handler
			push	fs : [0]
			mov		fs : [0], esp				// SEH Chain Install

			mov		eax, 1
			xor		ecx, ecx
			div		ecx					// Exception Divide by Zero

			mov		eax, dword ptr[esp]
			mov		fs : [0], eax
			add		esp, 8
	}
}


// INT2D
BOOL anti_debug_flag_int2d = TRUE;
void int2d() {
	__try {
		__asm {
			int 0x2d
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		anti_debug_flag_int2d = FALSE;
	}
}

//int3
BOOL anti_debug_flag_int3 = TRUE;

void int3()
{
	__try
	{
		__asm { int 3 }
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		anti_debug_flag_int3 = FALSE;
	}
}


//Magic Number
void magicnumber_ldr()
{
	void *pLdr;
	DWORD data, *base;

	__asm
	{
		mov eax, fs:[0x30]				// PEB Address
			mov eax, dword ptr[eax + 0xc]	// LDR Address
			mov pLdr, eax;
	}

	base = (DWORD *)pLdr;

	while (1) {
		data = *base++;
		if (data == 0xfeeefeee)	break;
	}
}

void magicnumber_heap()
{
	void *pHeap;
	DWORD data, *base;

	__asm
	{
		mov eax, fs:[0x30]				// PEB Address
			mov eax, dword ptr[eax + 0x18]	// HEAP Address
			mov pHeap, eax;
	}

	base = (DWORD *)pHeap;

	while (1) {
		data = *base++;
		if (data == 0xfeeefeee)	break;
	}
}

BOOL magicNumber()
{
	BOOL result = TRUE;

	__try
	{
		magicnumber_heap();
		magicnumber_ldr();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		result = FALSE;
	}
	return result;
}


// Memory break point
bool MemoryBreakpointDebuggerCheck()
{
	unsigned char *pMem = NULL;
	SYSTEM_INFO sysinfo = { 0 };
	DWORD OldProtect = 0;
	void *pAllocation = NULL; // Get the page size for the system 

	GetSystemInfo(&sysinfo); // Allocate memory 

	pAllocation = VirtualAlloc(NULL, sysinfo.dwPageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (pAllocation == NULL)
		return false;

	// Write a ret to the buffer (opcode 0xc3)
	pMem = (unsigned char*)pAllocation;
	*pMem = 0xc3;

	// Make the page a guard page         
	if (VirtualProtect(pAllocation, sysinfo.dwPageSize,
		PAGE_EXECUTE_READWRITE | PAGE_GUARD,
		&OldProtect) == 0)
	{
		return false;
	}

	__try
	{
		__asm
		{
			mov eax, pAllocation
			// This is the address we'll return to if we're under a debugger
			push MemBpBeingDebugged
			jmp eax // Exception or execution, which shall it be 
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// The exception occured and no debugger was detected
		VirtualFree(pAllocation, NULL, MEM_RELEASE);
		return false;
	}

	__asm{MemBpBeingDebugged:}
	VirtualFree(pAllocation, NULL, MEM_RELEASE);
	return true;
}

//NTGlobalFlag
DWORD ntGlobalFlag()
{
	__asm
	{
		mov eax, fs:[0x30]
		movzx eax, dword ptr [eax+0x68]
	}
}


// NtQueryInformationProcess_ProcessDebugFlags

typedef DWORD(WINAPI *PFZWQUERYINFORMATIONPROCESS) (
	HANDLE		ProcessHandle,
	DWORD		ProcessInformationClass,	// Origianl : _PROCESS_INFORMATION_CLASS
	PVOID		ProcessInformation,
	ULONG		ProcessInformationLength,
	PULONG		ReturnLength
	);

BOOL Nt_QIP_flag()
{
	BOOL result = FALSE;
	DWORD fRet;
	DWORD ProcessDebugFlags;

	PFZWQUERYINFORMATIONPROCESS pfZwQueryInformationProcess;
	HMODULE h_ntdll = GetModuleHandle(L"ntdll.dll");
	pfZwQueryInformationProcess = (PFZWQUERYINFORMATIONPROCESS)GetProcAddress(h_ntdll, "ZwQueryInformationProcess");
	fRet = pfZwQueryInformationProcess(GetCurrentProcess(), 0x1f, &ProcessDebugFlags, 4, 0);	// 0x1f : ProcessDebugFlags
	if (!ProcessDebugFlags) result = TRUE;	
	return result;
}


BOOL Nt_QIP_objectHandle()
{
	BOOL result = FALSE;
	DWORD fRet;
	DWORD ProcessDebugObejctHandle;

	PFZWQUERYINFORMATIONPROCESS pfZwQueryInformationProcess;
	HMODULE h_ntdll = GetModuleHandle(L"ntdll.dll");
	pfZwQueryInformationProcess = (PFZWQUERYINFORMATIONPROCESS)GetProcAddress(h_ntdll, "ZwQueryInformationProcess");
	fRet = pfZwQueryInformationProcess(GetCurrentProcess(), 0x1e, &ProcessDebugObejctHandle, 4, 0);	// 0x1e : ProcessObjectHandle
	if (ProcessDebugObejctHandle) result = TRUE;	
	if (fRet == 0) result = TRUE;				
	return result;
}

//NtQueryInformationProcess_ProcessDebugPort
BOOL Nt_QIP_debugPort()
{
	BOOL result = FALSE;
	DWORD ProcessDebugPort;

	PFZWQUERYINFORMATIONPROCESS pfZwQueryInformationProcess;
	HMODULE h_ntdll = GetModuleHandle(L"ntdll.dll");
	pfZwQueryInformationProcess = (PFZWQUERYINFORMATIONPROCESS)GetProcAddress(h_ntdll, "ZwQueryInformationProcess");
	pfZwQueryInformationProcess(GetCurrentProcess(), 0x7, &ProcessDebugPort, 4, 0);	// 0x7 : ProcessDebugPort
	if (ProcessDebugPort == -1) result = TRUE;
	return result;
}


//NtQueryPerformanceCounter
BOOL Nt_QIP_performanceCounter(LARGE_INTEGER cnt1)
{
	LARGE_INTEGER cnt2;
	QueryPerformanceCounter(&cnt2);
	if ((cnt2.QuadPart - cnt1.QuadPart) > 0xFF) {
		return 1;
	}
	return 0;
}
	


//Ollydbg_static
BOOL ollydbg()
{
	DWORD All_process[1024], cb, process_cnt, value;
	int read;
	unsigned int i;
	HMODULE hMod = NULL;
	HANDLE hProcess;

	EnumProcesses(All_process, sizeof(All_process), &cb);
	process_cnt = cb / sizeof(DWORD);
	for (i = 0; i < process_cnt; i++){
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, All_process[i]);
		if (hProcess != NULL) {
			value = 0;
			if (ReadProcessMemory(hProcess, (LPCVOID)0x4B064B, &value, (SIZE_T)4, (SIZE_T *)&read)) {
				if (value == 0x594C4C4F) {
					return 1;
				}
			}
		}
	}
	return 0;
}

//OutputDebugString
BOOL outDebugString_0()
{
	DWORD Val = 123;
	SetLastError(Val);
	OutputDebugString(L"random");
	if (GetLastError() == Val) {
		return 1;
	}
	else {
		return 0;
	}
}

//OutputDebugStringBug
BOOL outDebugString_1()
{
	DWORD Val = 123;
	SetLastError(Val);
	OutputDebugString(L"%s%s%s%s%s%s%s%s");
	if (GetLastError() == Val) {
		return 1;
	}
	else {
		return 0;
	}
}

// Parent process
int GetProcssName(DWORD PID, char *buff, int size)
{
    int len = 0;
    HANDLE hProc = NULL;

    if ( (hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID)) != NULL)
    {
        len = GetModuleBaseName(hProc, NULL, (LPWSTR)buff, size);
        CloseHandle (hProc);
    }

    return len;
}

bool parentProcess()
{
    int pid = -1, len;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { 0 };
    char name[100];
	pe.dwSize = sizeof(PROCESSENTRY32);
	pid = GetCurrentProcessId();
  
    if( Process32First(h, &pe)) {
    	do {
    		if (pe.th32ProcessID == pid) {
    			break;
    		}
    	} while( Process32Next(h, &pe));
    }
    CloseHandle(h);
	len = GetProcssName(pe.th32ParentProcessID, name, sizeof(name)-1);
	name[len]=0;
	if(!memcmp(name, "OllyDbg",4)){
		return 1;
	}
	return 0;
}


// prefix 

// The IsDbgPresentPrefixCheck works in at least two debuggers
// OllyDBG and VS 2008, by utilizing the way the debuggers handle
// prefixes we can determine their presence. Specifically if this code
// is ran under a debugger it will simply be stepped over;
// however, if there is no debugger SEH will fire :D
inline bool IsDbgPresentPrefixCheck()
{
	__try
	{
		__asm __emit 0xF3 // 0xF3 0x64 disassembles as PREFIX REP:
		__asm __emit 0x64
		__asm __emit 0xF1 // One byte INT 1
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}



// Single step
BOOL anti_debug_flag_singleStep = TRUE;
void singleStep()
{
	__try
	{
		__asm
		{
			pushfd
				or dword ptr ss : [esp + 1], 1	// or dword ptr ss:[esp], 0x100
				popfd
				nop
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		anti_debug_flag_singleStep = FALSE;
	}
}

//Unhandled exception filter
LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers)
{
	// Restore old UnhandledExceptionFilter
	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)
		pExcepPointers->ContextRecord->Eax);

	// Skip the exception code
	pExcepPointers->ContextRecord->Eip += 2;

	return EXCEPTION_CONTINUE_EXECUTION;
}


// timeGetTime
BOOL time_get(DWORD time1)
{
	DWORD time2;
	time2 = timeGetTime();

	if ((time2 - time1) > 0x10) {
		return 1;
	}
	return 0;
}

int	numLen(int num){
	int digits = 0;
	while (num != 0) {
        num /= 10;
        digits++;
    }
	return digits;
}

int main(int argc, char* argv[])
{
SYSTEMTIME s_time1;
FILETIME f_time1;
GetSystemTime(&s_time1);
SystemTimeToFileTime(&s_time1, &f_time1);
DWORD count1;
count1 = GetTickCount();

int2d();
int3();
LARGE_INTEGER cnt1;
QueryPerformanceCounter(&cnt1);

singleStep();
DWORD time1;
time1 = timeGetTime();

	if(debuggerPresent() || beeingDebugged() || CheckRemoteDebuggerPresent() || CloseHandle_InvalideHandle() || findWindow() || sysTimeDiff(s_time1, f_time1) || tickCount(count1) || hardwareBreakPoint_ThreadContext() || anti_debug_flag_seh || anti_debug_flag_int2d || anti_debug_flag_int3 || magicNumber() || MemoryBreakpointDebuggerCheck() || ntGlobalFlag() || Nt_QIP_flag() || Nt_QIP_objectHandle() || Nt_QIP_debugPort() || Nt_QIP_performanceCounter(cnt1) || ollydbg() || outDebugString_0() || outDebugString_1() || parentProcess() || IsDbgPresentPrefixCheck() || anti_debug_flag_singleStep || time_get(time1))
	{
		exit(1);
	}
	if (argc < 2){
		printf("Usage: Program.exe <key>\n");
		return 0;
	}
	int number = atoi(argv[1]);
	if (numLen(number) < 8) {
		printf("%d\n", number);
		if (number == key){	printf("Nice ! You have found the key\n");}
	} else {
		printf("The Key must be a number of less than 8 digits long.\n");
	}
	return 0;
}
