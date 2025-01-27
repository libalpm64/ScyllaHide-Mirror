#pragma once

#include <windows.h>

bool isWindows64();
bool CheckPidWOW64(DWORD dwPid);
bool IsProcessWOW64(HANDLE hProcess);
bool IsSysWow64();

enum eOperatingSystem {
	OS_UNKNOWN,
	OS_INVALID,
	OS_WIN_2000,
	OS_WIN_XP,
	OS_WIN_XP64,
	OS_WIN_VISTA, 
	OS_WIN_7, 
	OS_WIN_8, 
	OS_WIN_81, 
	OS_WIN_10
};

eOperatingSystem GetWindowsVersion();
const char * GetWindowsVersionNameA();

void GetPEBWindowsMajorMinorVersion(DWORD * major, DWORD * minor);
bool _IsWindows8Point1OrGreater();
bool _IsWindows10OrGreater();

