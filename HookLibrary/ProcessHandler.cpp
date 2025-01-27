#include "ProcessHandler.h"
#include <tlhelp32.h>

DWORD GetProcessIdByName(const WCHAR * processName)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	DWORD pid = 0;

	do
	{
		if (!lstrcmpiW(pe32.szExeFile, processName))
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return pid;
}