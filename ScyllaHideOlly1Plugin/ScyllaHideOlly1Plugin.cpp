#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "resource.h"
#include "..\PluginGeneric\Injector.h"
#include "..\PluginGeneric\ScyllaHideVersion.h"
#include "ollyplugindefinitions.h"
#include "olly1patches.h"
#include "..\InjectorCLI\RemotePebHider.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\UpdateCheck.h"
#include "..\PluginGeneric\IniSettings.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "..\PluginGeneric\AttachDialog.h"
#include "..\PluginGeneric\CustomExceptionHandler.h"
#include "..\InjectorCLI\OperatingSysInfo.h"

typedef void (__cdecl * t_AttachProcess)(DWORD dwPID);
typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);
typedef void (__cdecl * t_SetDebuggerBreakpoint)(DWORD_PTR address);
typedef bool (__cdecl * t_IsAddressBreakpoint)(DWORD_PTR address);

void LogWrapper(const WCHAR * format, ...);
void LogErrorWrapper(const WCHAR * format, ...);
void AttachProcess(DWORD dwPID);
void SetDebuggerBreakpoint(DWORD_PTR address);
bool __cdecl IsAddressBreakpoint(DWORD_PTR address);

//scyllaHide definitions
struct HideOptions pHideOptions = {0};

const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";
const WCHAR ScyllaHideIniFilename[] = L"scylla_hide.ini";

//globals
HINSTANCE hinst;
DWORD ProcessId;
DWORD_PTR epaddr = 0;
bool bHooked = false;
static bool bEPBreakRemoved = false;
HWND hwmain; // Handle of main OllyDbg window
bool bHookedDumpProc = false;

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};
WCHAR ScyllaHideIniPath[MAX_PATH] = {0};

extern WCHAR CurrentProfile[MAX_SECTION_NAME];
extern WCHAR ProfileNames[2048];
extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;
extern t_AttachProcess _AttachProcess;
extern t_SetDebuggerBreakpoint _SetDebuggerBreakpoint;
extern t_IsAddressBreakpoint _IsAddressBreakpoint;

HMODULE hNtdllModule = 0;
bool specialPebFix = false;
LPVOID ImageBase = 0;

bool executeOnce = false;

void MarkSystemDllsOnx64();
void HandleDetachProcess();
DEBUG_EVENT *currentDebugEvent;

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved)
{ 
	if (reason == DLL_PROCESS_ATTACH)
	{
		_AttachProcess = AttachProcess;
		LogWrap = LogWrapper;
		LogErrorWrap = LogErrorWrapper;
		_IsAddressBreakpoint = IsAddressBreakpoint;
		hNtdllModule = GetModuleHandleW(L"ntdll.dll");
		GetModuleFileNameW(hi, NtApiIniPath, _countof(NtApiIniPath));
		WCHAR *temp = wcsrchr(NtApiIniPath, L'\\');
		if (temp)
		{
			temp++;
			*temp = 0;
			wcscpy(ScyllaHideDllPath, NtApiIniPath);
			wcscat(ScyllaHideDllPath, ScyllaHideDllFilename);
			wcscpy(ScyllaHideIniPath, NtApiIniPath);
			wcscat(ScyllaHideIniPath, ScyllaHideIniFilename);
			wcscat(NtApiIniPath, NtApiIniFilename);
		}

		hinst=hi;
	}
	return TRUE;
};

//register plugin with name
extern "C" int __declspec(dllexport) _ODBG_Plugindata(char shortname[32])
{
	strcpy(shortname,"ScyllaHide");
	return PLUGIN_VERSION;
};

//initialization happens in here
extern "C" int __declspec(dllexport) _ODBG_Plugininit(int ollydbgversion,HWND hw,unsigned long *features)
{
	if (ollydbgversion<PLUGIN_VERSION)
		return -1;

	hwmain=hw;

	ReadCurrentProfile();
	ReadSettings();

	_Addtolist(0,0,"ScyllaHide Plugin v" SCYLLA_HIDE_VERSION_STRING_A);
	_Addtolist(0,-1,"  Copyright (C) 2014 Aguila / cypher");
	_Addtolist(0,-1,"  Operating System: %s", GetWindowsVersionNameA());

	//do some Olly fixes
	if(pHideOptions.fixOllyBugs) {
		fixBadPEBugs();
		fixForegroundWindow();
		fixFPUBug();
		fixSprintfBug();
		fixNTSymbols();
		fixFaultyHandleOnExit();
	}
	if(pHideOptions.x64Fix && isWindows64()) {
		fixX64Bug();
	}
	if(pHideOptions.skipEPOutsideCode) {
		patchEPOutsideCode();
	}

	if(pHideOptions.killAntiAttach) {
		InstallAntiAttachHook();
	}

	if(pHideOptions.ignoreBadPEImage) {
		fixBadPEImage();
	}

	if(pHideOptions.advancedGoto) {
		advcancedCtrlG();
	};

	if(pHideOptions.skipCompressedDoAnalyze || pHideOptions.skipCompressedDoNothing) {
		skipCompressedCode();
	}

	if(pHideOptions.skipLoadDllDoLoad || pHideOptions.skipLoadDllDoNothing) {
		skipLoadDll();
	}
	return 0;
};

// OllyDbg calls this optional function when user wants to terminate OllyDbg.
// All MDI windows created by plugins still exist. Function must return 0 if
// it is safe to terminate. Any non-zero return will stop closing sequence. Do
// not misuse this possibility! Always inform user about the reasons why
// termination is not good and ask for his decision!
extern "C" int __declspec(dllexport) _ODBG_Pluginclose(void)
{
	//TODO RestoreAllHooks();
	return 0;
}

//add menu entries
extern "C" int __declspec(dllexport) _ODBG_Pluginmenu(int origin,char data[4096],void *item)
{
	switch(origin)
	{
	case PM_MAIN:
		{
			char sectionNamesA[2048] = {0};
			GetProfileNames(sectionNamesA);
			strcpy(data, "0 &Options, 4 &Load Profile");
			strcat(data, sectionNamesA);
			strcat(data, ",|2 &Inject DLL|5 &Attach process, 6 &Detach process|3 &Update-Check, 1 &About");

			//also patch olly title
			SetWindowTextW(hwmain, pHideOptions.ollyTitle);
			return 1;
		}
	case PM_THREADS:
		{
			strcpy(data, "0 &Resume all Threads, 1 &Suspend all Threads");
			return 1;
		}

	default:
		break;
	}


	return 0;
}

//handle plugin actions
extern "C" void __declspec(dllexport) _ODBG_Pluginaction(int origin,int action,void *item)
{
	if(origin==PM_MAIN) {
		switch(action)
		{
		case 0:
			{
				DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwmain, &OptionsProc);
				break;
			}
		case 1:
			{
				ShowAbout(hwmain);

				break;
			}
		case 2:
			{
				if(ProcessId) {
					wchar_t dllPath[MAX_PATH] = {};
					if(GetFileDialog(dllPath))
						injectDll(ProcessId, dllPath);
				}
				break;
			}
		case 3:
			{
				if(isNewVersionAvailable()) {
					MessageBoxA(hwmain,
						"There is a new version of ScyllaHide available !\n\n"
						"Check out https://bitbucket.org/NtQuery/scyllahide/downloads \n"
						"or some RCE forums !",
						"ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
				}
				else {
					MessageBoxA(hwmain,
						"You already have the latest version of ScyllaHide !",
						"ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
				}

				break;
			}
		case 5:
			{
				DialogBox(hinst, MAKEINTRESOURCE(IDD_ATTACH), hwmain, &AttachProc);
				break;
			}
		case 6:
			{
				HandleDetachProcess();
				break;
			}
			//profile names/count is dynamic so we catch loading them with default case
		default: {
			SetCurrentProfile(action);
			ReadSettings();

			if (ProcessId)
			{
				startInjection(ProcessId, ScyllaHideDllPath, true);
				bHooked = true;
				MessageBoxA(hwmain, "Applied changes! Restarting target is NOT necessary!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
			}
			else
			{
				MessageBoxA(hwmain, "Please start the target to apply changes!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
			}
				 }
				 break;
		}
	} else if(origin==PM_THREADS) {
		t_table* threadWindow = (t_table*)_Plugingetvalue(VAL_THREADS);
		int threadCount = threadWindow->data.n;
		int threadSize = threadWindow->data.itemsize;
		t_thread* thread = (t_thread*)threadWindow->data.data;

		switch(action)
		{
		case 0:
			{
				//resume
				for(int i=0; i<threadCount; i++) {
					ResumeThread(thread->thread);

					//yup this is super-hacky-pointer-kungfu but thread++ wont work coz there
					//is 0x20bytes extra data between thread elements
					thread = reinterpret_cast<t_thread*>((DWORD)thread+threadSize);
				}
				break;
			}
		case 1:
			{
				//suspend
				for(int i=0; i<threadCount; i++) {
					SuspendThread(thread->thread);

					//yup this is super-hacky-pointer-kungfu but thread++ wont work coz there
					//is 0x20bytes extra data between thread elements
					thread = reinterpret_cast<t_thread*>((DWORD)thread+threadSize);
				}
				break;
			}
		}
	}
}

//called for every debugloop pass
extern "C" void __declspec(dllexport) _ODBG_Pluginmainloop(DEBUG_EVENT *debugevent)
{
	if(!debugevent)
		return;

	if (pHideOptions.PEBHeapFlags)
	{
		if (specialPebFix)
		{
			StartFixBeingDebugged(ProcessId, false);
			specialPebFix = false;
		}

		if (debugevent->u.LoadDll.lpBaseOfDll == hNtdllModule)
		{
			StartFixBeingDebugged(ProcessId, true);
			specialPebFix = true;
		}
	}

	switch(debugevent->dwDebugEventCode)
	{
	case CREATE_PROCESS_DEBUG_EVENT:
		{

			if (pHideOptions.handleExceptionPrint || 
				pHideOptions.handleExceptionRip ||
				pHideOptions.handleExceptionIllegalInstruction ||
				pHideOptions.handleExceptionInvalidLockSequence ||
				pHideOptions.handleExceptionNoncontinuableException ||
				pHideOptions.handleExceptionBreakpoint ||
				pHideOptions.handleExceptionWx86Breakpoint ||
				pHideOptions.handleExceptionGuardPageViolation
				)
			{
				if (executeOnce == false)
				{
					HookDebugLoop();
					executeOnce = true;
				}
			}

			ImageBase = debugevent->u.CreateProcessInfo.lpBaseOfImage;
			ProcessId=debugevent->dwProcessId;
			bHooked = false;
			epaddr = (DWORD_PTR)debugevent->u.CreateProcessInfo.lpStartAddress;

			if (epaddr == NULL)
			{
				//ATTACH to an existing process!
				//Apply anti-anti-attach
				if(pHideOptions.killAntiAttach)
				{
					if (!ApplyAntiAntiAttach(ProcessId))
					{
						MessageBoxW(hwmain, L"Anti-Anti-Attach failed", L"Error", MB_ICONERROR);
					}
				}
			}

			ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

			//change olly caption again !
			SetWindowTextW(hwmain, pHideOptions.ollyTitle);

			if(!bHookedDumpProc) {
				hookOllyWindowProcs();
				bHookedDumpProc = true;
			}
			hookOllyBreakpoints();
		}
		break;

	case LOAD_DLL_DEBUG_EVENT:
		{
			if (bHooked)
			{
				if(pHideOptions.fixOllyBugs && isWindows64()) {
					MarkSystemDllsOnx64();
				}

				startInjection(ProcessId, ScyllaHideDllPath, false);
			}
			break;
		}
	case EXCEPTION_DEBUG_EVENT:
		{
			currentDebugEvent = debugevent;

			switch(debugevent->u.Exception.ExceptionRecord.ExceptionCode)
			{
			case STATUS_BREAKPOINT:
				{
					if (!bHooked)
					{
						_Message(0, "[ScyllaHide] Reading NT API Information %S", NtApiIniPath);
						ReadNtApiInformation();

						bHooked = true;
						startInjection(ProcessId, ScyllaHideDllPath, true);
					}

					break;
				}

			case STATUS_ILLEGAL_INSTRUCTION:
				{
					//THEMIDA
					break;
				}
			}

			break;
		}
	}
}

//reset variables. new target started or restarted
extern "C" void __declspec(dllexport) _ODBG_Pluginreset(void)
{
	ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
	bHooked = false;
	bEPBreakRemoved = false;
	ProcessId = 0;
}

void LogErrorWrapper(const WCHAR * format, ...)
{
	WCHAR text[2000];
	CHAR textA[2000];
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfW(text, format, va_alist);

	WideCharToMultiByte(CP_ACP,0,text,-1,textA, _countof(textA), 0,0);

	_Error("%s",textA);
}

void LogWrapper(const WCHAR * format, ...)
{
	WCHAR text[2000];
	CHAR textA[2000];
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfW(text, format, va_alist);

	WideCharToMultiByte(CP_ACP,0,text,-1,textA, _countof(textA), 0,0);

	_Message(0,"%s", textA);
}

void AttachProcess(DWORD dwPID)
{
	int result = _Attachtoactiveprocess((int)dwPID);

	if (result != 0)
	{
		MessageBoxW(hwmain,
			L"Can't attach to that process !",
			L"ScyllaHide Plugin",MB_OK|MB_ICONERROR);
	}
}

bool __cdecl IsAddressBreakpoint(DWORD_PTR address)
{
	t_table* pTable=(t_table*)_Plugingetvalue(VAL_BREAKPOINTS);
	if(pTable)
	{
		t_sorted* pSorted = &(pTable->data);
		for(int i=0;i<pTable->data.n;i++)
		{
			t_bpoint* bp=(t_bpoint*)_Getsortedbyselection(pSorted,i);
			if (bp)
			{
				//char text[100];
				//wsprintfA(text,"%X %X",bp->addr,address);
				//MessageBoxA(0,text,text,0);
				if (bp->addr == address)
				{
					return true;
				}
			}
		}
	}

	return false;
}

void MarkSystemDllsOnx64() {
	const char sysPath[] = "windows\\syswow64";
	char lowerCopy[MAX_PATH] = {0};

	int t = _Plugingetvalue(VAL_MODULES);
	if(t <= 0)  {
		_Error("Cannot get module list");
		return;
	}

	t_table* ttab = (t_table*)t;
	t_module* tmod;
	for(int i = 0; i < ttab->data.n; i++)
	{
		tmod = (t_module*)_Getsortedbyselection(&ttab->data, i);

		for(int j = 0; tmod->path[j]; j++) {
			lowerCopy[j] = tolower(tmod->path[j]);
		}

		//skip C:/
		if (strncmp(lowerCopy + 3, sysPath, sizeof(sysPath) - 1) == 0) {
			tmod->issystemdll = 1;
		} else {
			//MessageBoxA(0, lowerCopy, "NON",0);
		}

	}
}

void PrepareDetach() {
	//delete breakpoints

	t_table* pTable=(t_table*)_Plugingetvalue(VAL_BREAKPOINTS);
	if(pTable)
	{
		t_sorted* pSorted = &(pTable->data);

		//IMPORTANT: Reverse index loop
		for(int i = pTable->data.n - 1; i >= 0; i--)
		{
			t_bpoint* pBreakpoint = (t_bpoint*)_Getsortedbyselection(pSorted, i);
			if(pBreakpoint)	{
				_Deletebreakpoints(pBreakpoint->addr, (pBreakpoint->addr)+1, TRUE);   //silent
			}
		}

	}
}

void HandleDetachProcess()
{
	t_status tStat = _Getstatus();

	if(tStat != STAT_STOPPED && tStat != STAT_RUNNING)
	{
		MessageBoxW(hwmain, L"Process must be in paused or running mode.", L"Detach Error", MB_ICONERROR);
		return;
	}

	PrepareDetach();

	tStat = _Getstatus();

	if(tStat == STAT_STOPPED) {
		if (currentDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

			HANDLE hThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, FALSE, currentDebugEvent->dwThreadId);
			if (hThread) {
				CONTEXT context = {0};
				context.ContextFlags = CONTEXT_ALL;
				GetThreadContext(hThread, &context);
				context.Eip = (DWORD)currentDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;
				SetThreadContext(hThread, &context);
				CloseHandle(hThread);

				ContinueDebugEvent(currentDebugEvent->dwProcessId, currentDebugEvent->dwThreadId, DBG_CONTINUE);
			}

		} else if (currentDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
			ContinueDebugEvent(currentDebugEvent->dwProcessId, currentDebugEvent->dwThreadId, DBG_CONTINUE);
		} else {
			ContinueDebugEvent(currentDebugEvent->dwProcessId, currentDebugEvent->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
		}
	}

	DebugSetProcessKillOnExit(FALSE);
	
	//terminate olly
	ExitProcess(0);
}
