#include "pch.h"
#include <VersionHelpers.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <Psapi.h>
#include "WError.h"

#define DLL_NAME "GGXrdDisplayPing.dll"
#define DLL_NAMEW L"GGXrdDisplayPing.dll"

DWORD findOpenGgProcess();

bool force = false;
ULONGLONG startTime = 0;

std::wostream& operator<<(std::wostream& stream, const WinError& err) {
	return stream << L"0x" << std::hex << err.code << L' ' << err.message << L'\n';
}

MODULEENTRY32W findModuleUsingEnumProcesses(DWORD procId, const wchar_t* name) {
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
	if (!proc || proc == INVALID_HANDLE_VALUE) {
		WinError winErr;
		std::wcout << L"Failed to open process: " << winErr << std::endl;
		return MODULEENTRY32W{0};
	}
	HMODULE hMod[1024];
	DWORD bytesReturned = 0;
	if (!EnumProcessModulesEx(proc, hMod, sizeof hMod, &bytesReturned, LIST_MODULES_32BIT)) {
		WinError winErr;
		std::wcout << L"EnumProcessModulesEx failed: " << winErr << std::endl;
		CloseHandle(proc);
		return MODULEENTRY32W{0};
	}
	if (bytesReturned == 0) {
		WinError winErr;
		std::wcout << L"EnumProcessModulesEx returned 0 bytes.\n";
		CloseHandle(proc);
		return MODULEENTRY32W{0};
	}
	wchar_t baseName[1024] { L'\0' };
	int maxI = bytesReturned / sizeof HMODULE;
	for (int i = 0; i < maxI; ++i) {
		if (!GetModuleBaseNameW(proc, hMod[i], baseName, _countof(baseName))) {
			WinError winErr;
			std::wcout << L"GetModuleBaseNameW failed: " << winErr << std::endl;
			CloseHandle(proc);
			return MODULEENTRY32W{0};
		}
		if (_wcsicmp(baseName, DLL_NAMEW) == 0) {
			MODULEINFO info;
			if (!GetModuleInformation(proc, hMod[i], &info, sizeof MODULEINFO)) {
				WinError winErr;
				std::wcout << L"GetModuleInformation failed: " << winErr << std::endl;
				CloseHandle(proc);
				return MODULEENTRY32W{0};
			}
			
			MODULEENTRY32W result;
			result.modBaseAddr = (BYTE*)info.lpBaseOfDll;
			CloseHandle(proc);
			std::cout << "EnumProcessModulesEx workaround worked.\n";
			return result;
		}
	}
	std::cout << "EnumProcessModulesEx workaround worked.\n";
	CloseHandle(proc);
	return MODULEENTRY32W{0};
}

// Finds module (a loaded dll or exe itself) in the given process by name.
// If module is not found, the returned module will have its modBaseAddr equal to 0.
// Parameters:
//  procId - process ID (PID)
//  name - the name of the module, including the .exe or .dll at the end
//  is32Bit - specify true if the target process is 32-bit
MODULEENTRY32W findModule(DWORD procId, const wchar_t* name, bool is32Bit) {
	HANDLE hSnapshot = NULL;
	MODULEENTRY32W mod32{ 0 };
	mod32.dwSize = sizeof(MODULEENTRY32W);
	while (true) {
		// If you're a 64-bit process trying to get modules from a 32-bit process,
		// use TH32CS_SNAPMODULE32.
		// If you're a 64-bit process trying to get modules from a 64-bit process,
		// use TH32CS_SNAPMODULE.
		hSnapshot = CreateToolhelp32Snapshot(is32Bit ? (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32) : TH32CS_SNAPMODULE, procId);
		if (hSnapshot == INVALID_HANDLE_VALUE || !hSnapshot) {
			WinError err;
			if (err.code == ERROR_BAD_LENGTH) {
				continue;
			} else {
				std::wcout << L"Error in CreateToolhelp32Snapshot: " << err << std::endl << L"Is this running under Wine on Linux?\n";
				std::cout << "Will attempt EnumProcessModulesEx workaround.\n";
				return findModuleUsingEnumProcesses(procId, name);
			}
		}
		else {
			break;
		}
	}
	if (!Module32FirstW(hSnapshot, &mod32)) {
		WinError winErr;
		std::wcout << L"Error in Module32First: " << winErr << std::endl;
		CloseHandle(hSnapshot);
		return MODULEENTRY32W{ 0 };
	}
	while (true) {
		if (CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, mod32.szModule, -1, name, -1) == CSTR_EQUAL) {
			CloseHandle(hSnapshot);
			return mod32;
		}
		BOOL resNext = Module32NextW(hSnapshot, &mod32);
		if (!resNext) {
			WinError err;
			if (err.code != ERROR_NO_MORE_FILES) {
				std::wcout << L"Error in Module32Next: " << err << std::endl;
				CloseHandle(hSnapshot);
				return MODULEENTRY32W{ 0 };
			}
			break;
		}
	}
	CloseHandle(hSnapshot);
	return MODULEENTRY32W{ 0 };
}

void printTooSmall() {
	DWORD res = GetCurrentDirectoryW(0, NULL);
	std::wstring path(res - 1, L'\0');
	GetCurrentDirectoryW(res, &path.front());
	std::wcout << "The working directory path '" << path << "' + '\\' + '" DLL_NAME "' does not fit into " << MAX_PATH - 1 << " characters.\n";
}

bool constructPath(wchar_t* dllPath) {
	#define exitTooSmall { printTooSmall(); return false; }
	DWORD res = GetCurrentDirectoryW(MAX_PATH, dllPath);
	if (dllPath[0] == L'\0' && res) exitTooSmall
	if (!res) {
		WinError err;
		std::wcout << "Failed to call GetCurrentDirectoryW: " << err << std::endl;
		return false;
	}
	// wcscat_s crashes when buffer is too small
	if (dllPath[MAX_PATH - 1] != L'\0') exitTooSmall
	wcscat_s(dllPath, MAX_PATH, L"\\");
	if (wcslen(dllPath) + wcslen(DLL_NAMEW) >= MAX_PATH) exitTooSmall
	wcscat_s(dllPath, MAX_PATH, DLL_NAMEW);
	return true;
	#undef exitTooSmall
}

struct Cleanup {
	LPVOID virtualMem = NULL;
	HANDLE proc = NULL;
	~Cleanup() {
		if (virtualMem) {
			VirtualFreeEx(proc, virtualMem, 0, MEM_RELEASE);
		}
		for (int i = count - 1; i >= 0; --i) {
			CloseHandle(handles[i]);
		}
	}
	void addHandle(HANDLE hndl) {
		if (count >= _countof(handles)) {
			std::cout << "Cannot clean up more than " << _countof(handles) << " handles.\n";
			return;
		}
		handles[count++] = hndl;
	}
private:
	HANDLE handles[10] { NULL };
	int count = 0;
};

bool inject(HANDLE proc) {
	
	Cleanup cleanup;
	cleanup.proc = proc;
	
	wchar_t dllPath[MAX_PATH] { L'\0' };
	if (!constructPath(dllPath)) return false;
	
	std::wcout << L"Dll path: " << dllPath << std::endl;
	
	DWORD dllAtrib = GetFileAttributesW(dllPath);
	if (dllAtrib == INVALID_FILE_ATTRIBUTES) {
		WinError winErr;
		std::wcout << winErr << std::endl;
		return false;
	}
	if ((dllAtrib & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		std::cout << "The found DLL is actually a directory. Terminating.\n";
		return false;
	}
	
	SIZE_T size = (wcslen(dllPath) + 1) * sizeof(wchar_t);
	
	LPVOID buf = VirtualAllocEx(proc, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (buf == NULL) {
		WinError winErr;
		std::wcout << L"Failed to allocate memory: " << winErr << "\n";
		return false;
	}
	cleanup.virtualMem = buf;
	std::cout << "Allocated memory: " << buf << std::endl;
	
	if (!WriteProcessMemory(proc, buf, dllPath, size, nullptr)) {
		WinError winErr;
		std::wcout << L"Failed to write memory: " << winErr << "\n";
		return false;
	}
	std::cout << "Wrote memory successfully.\n";
	
	HANDLE newThread = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)(LoadLibraryW), buf, 0, nullptr);
	if (newThread == INVALID_HANDLE_VALUE || newThread == NULL) {
		WinError winErr;
		std::wcout << L"Failed to create remote thread: " << winErr << std::endl;
		return false;
	}
	cleanup.addHandle(newThread);
	
	std::cout << "Injecting...\n";
	DWORD waitResult = WaitForSingleObject(newThread, INFINITE);
	if (waitResult == WAIT_OBJECT_0) {
		DWORD exitCode = 0;
		if (!GetExitCodeThread(newThread, &exitCode)) {
			WinError winErr;
			std::wcout << L"Failed to get the exit code of the injected thread: " << winErr << L'\n'
				<< L"Injection probably failed.\n";
			return false;
		} else if (exitCode == 0) {
			std::cout << "Injection failed.\n";
			return false;
		} else {
			std::cout << "Injected successfully. You can launch this injector again to unload the DLL.\n";
			return true;
		}
	} else if (waitResult == WAIT_FAILED) {
		WinError winErr;
		std::wcout << "WaitForSingleObject call failed: " << winErr << std::endl;
		return false;
	} else {
		std::wcout << "WaitForSingleObject call returned: " << waitResult << std::endl;
		return false;
	}
	
}

bool uninject(HANDLE proc, BYTE* modBaseAddr) {
	
	Cleanup cleanup;
	
	HANDLE newThread = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)(FreeLibrary), modBaseAddr, 0, nullptr);
	if (newThread == INVALID_HANDLE_VALUE || newThread == NULL) {
		WinError winErr;
		std::wcout << L"Failed to create remote thread: " << winErr << std::endl;
		return false;
	}
	cleanup.addHandle(newThread);
	
	std::cout << "Uninjecting...\n";
	DWORD waitResult = WaitForSingleObject(newThread, INFINITE);
	if (waitResult == WAIT_OBJECT_0) {
		DWORD exitCode = 0;
		if (!GetExitCodeThread(newThread, &exitCode)) {
			WinError winErr;
			std::wcout << L"Failed to get the exit code of the uninjecting thread: " << winErr << L'\n'
				<< L"Uninjection probably failed.\n";
			return false;
		} else if (exitCode == 0) {
			std::cout << "Uninjection failed.\n";
			return false;
		} else {
			std::cout << "Uninjected successfully. You can launch this injector again to inject back the DLL.\n";
			return true;
		}
	} else if (waitResult == WAIT_FAILED) {
		WinError winErr;
		std::wcout << "WaitForSingleObject call failed: " << winErr << std::endl;
		return false;
	} else {
		std::wcout << "WaitForSingleObject call returned: " << waitResult << std::endl;
		return false;
	}
}

bool injectOrUninject(DWORD pid) {
	std::wstring lineContents;
	
	Cleanup cleanup;
	
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (proc == NULL || proc == INVALID_HANDLE_VALUE) {
		WinError err;
		std::wcout << L"Failed to open process: " << err;
		return false;
	}
	cleanup.addHandle(proc);
	
	MODULEENTRY32W module = findModule(pid, DLL_NAMEW, true);
	if (module.modBaseAddr) {
		std::wcout << L"The " DLL_NAME " is already injected into the process (0x" << std::hex << (DWORD)module.modBaseAddr << std::dec << L")."
			L" Do you want to uninject it? (Type y/n and press Enter):\n";
		while (true) {
			if (!force) {
				std::getline(std::wcin, lineContents);
			} else {
				std::cout << "Force Y\n";
			}
			if (force || lineContents == L"y" || lineContents == L"Y") {
				return uninject(proc, module.modBaseAddr);
			} else if (lineContents == L"n" || lineContents == L"N") {
				std::cout << "The DLL won't be loaded a second time. No action will be taken.\n";
				return true;
			} else {
				std::cout << "Please type y or n and press Enter.\n";
			}
		}
	} else {
		std::cout << "The " DLL_NAME " is not yet loaded into the application. Do you want to load it? (Type y/n and press Enter):\n";
		while (true) {
			if (!force) {
				std::getline(std::wcin, lineContents);
			} else {
				std::cout << "Force Y\n";
			}
			if (force || lineContents == L"y" || lineContents == L"Y") {
				return inject(proc);
			} else if (lineContents == L"n" || lineContents == L"N") {
				std::cout << "The DLL won't be loaded.\n";
				return true;
			} else {
				std::cout << "Please type y or n and press Enter.\n";
			}
		}
	}
	return false;
}

int wmain(int argc, wchar_t** argv)
{
	startTime = GetTickCount64();
	
	for (int i = 0; i < argc; ++i) {
		if (_wcsicmp(*argv, L"-force") == 0) {
			force= true;
		} else if (_wcsicmp(*argv, L"/?") == 0
				|| _wcsicmp(*argv, L"--help") == 0
				|| _wcsicmp(*argv, L"-help") == 0) {
			std::cout << "Info: This program injects the '" DLL_NAME "' DLL into the GuiltyGearXrd.exe process."
				" Use -force option to not request any input from the user.\n";
			return 0;
		}
		++argv;
	}
	
	std::cout << "This program will inject the '" DLL_NAME "' DLL into the GuiltyGearXrd.exe process."
		" Make sure this injector and its DLL are located in the same folder.\n\n"
		"Waiting for Guilty Gear Xrd's window to open. Press any key to exit...\n";
	
	INPUT_RECORD records[10];
	HANDLE stdInHandle = GetStdHandle(STD_INPUT_HANDLE);
    while (true) {
    	DWORD eventsRead;
    	if (GetTickCount64() - startTime < 1000) {
    		eventsRead = 0;
    	} else if (!PeekConsoleInputW(stdInHandle, records, 10, &eventsRead)) {  // thanks, stdlib, for NOT having a non-blocking std::cin.peek
    		WinError err;
    		
    		std::cout << "Failed to call PeekConsoleInputW:\n"
    			<< "0x" << std::hex << err.code << std::dec << " ";
    		std::wcout << err.message << std::endl;
    		
    		return 1;
    	}
    	for (DWORD i = 0; i < eventsRead; ++i) {
    		const INPUT_RECORD& record = records[i];
    		if (record.EventType == KEY_EVENT
    				&& record.Event.KeyEvent.uChar.AsciiChar != 9  // TAB, as in Alt+TAB
    				&& record.Event.KeyEvent.wVirtualKeyCode != VK_CONTROL
    				&& record.Event.KeyEvent.wVirtualKeyCode != VK_LCONTROL
    				&& record.Event.KeyEvent.wVirtualKeyCode != VK_RCONTROL) {
    			return 0;
    		}
    	}
    	DWORD procId = findOpenGgProcess();
    	if (procId) {
    		std::cout << "Found PID: " << procId << '\n';
    		bool success = injectOrUninject(procId);
    		
    		if (!force || !success) {
	    		std::cout << "Press Enter to exit...\n";
	    		std::wstring ignoreLine;
	    		std::getline(std::wcin, ignoreLine);
    		}
    		return success ? 0 : 2;
    	}
    	Sleep(333);
    }
}

// Finds if GuiltyGearXrd.exe is currently open and returns the ID of its process
DWORD findOpenGgProcess() {
    // this method was chosen because it's much faster than enumerating all windows or all processes and checking their names
    // also it was chosen because Xrd restarts itself upon launch, and the window appears only on the second, true start
    HWND foundGgWindow = FindWindowW(L"LaunchUnrealUWindowsClient", L"Guilty Gear Xrd -REVELATOR-");
    if (!foundGgWindow) return NULL;
    DWORD windsProcId = 0;
    GetWindowThreadProcessId(foundGgWindow, &windsProcId);
    return windsProcId;
}
