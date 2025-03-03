#include "pch.h"
#include "Main.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    	if (!mod.attach(hModule)) {
    		mod.detach();
    		return FALSE;
    	}
    	break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    	break;
    case DLL_PROCESS_DETACH:
    	mod.detach();
        break;
    }
    return TRUE;
}
