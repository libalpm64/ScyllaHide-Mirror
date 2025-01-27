#include "IdaWindowSearch.h"

#include "..\HookLibrary\ProcessHandler.h"

DWORD GetIdaProcessId();
HWND FindWindowHwnd(DWORD pid);
BOOL CALLBACK EnumWindowsCallback(HWND handle, LPARAM lParam);

HWND GetIdaHwnd()
{
	DWORD idaPid = GetIdaProcessId();

	if (idaPid != 0)
	{
		return FindWindowHwnd(idaPid);
	}

	return 0;
}

DWORD GetIdaProcessId()
{
	DWORD idaPid = GetProcessIdByName(L"ida64.exe");

	if (idaPid == 0)
	{
		idaPid = GetProcessIdByName(L"ida.exe");
	}
	return idaPid;
}

struct CallbackData {
    DWORD Pid;
    HWND Handle;
};

HWND FindWindowHwnd(DWORD pid)
{
    CallbackData data;
    data.Pid = pid;
    data.Handle = 0;
    EnumWindows(EnumWindowsCallback, (LPARAM)&data);
    return data.Handle;
}

BOOL CALLBACK EnumWindowsCallback(HWND handle, LPARAM lParam)
{
    CallbackData * data = (CallbackData*)lParam;
    DWORD currentPid = 0;
    GetWindowThreadProcessId(handle, &currentPid);
	if (data->Pid != currentPid)
	{
        return TRUE;
	}
	data->Handle = handle;
    return FALSE;   
}