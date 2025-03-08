#pragma once
#include <vector>
#include "HandleWrapper.h"
#include "DrawTextWithIconsParams.h"

struct FString {
	void* Data;
	int ArrayNum;
	int ArrayMax;
};

using drawTextWithIcons_t = DWORD(__cdecl*)(DrawTextWithIconsParams* param_1, void* param_2, int param_3, int param_4, int param_5, int param_6);
using FStringAssignmentOperator_wchar_t_t = FString*(__thiscall*)(FString* thisArg, const wchar_t* Source);
using drawIcon_t = void(__cdecl*)(int iconIndex, DrawTextWithIconsParams* params, BOOL dontCommit);

class Main {
public:
	bool attach(HMODULE hModule);
	bool detach();
	bool unfreeze();
	bool eipIsIn(DWORD eip);
	
	bool includeThisModule = false;
	DWORD thisModuleStart = 0;
	DWORD thisModuleEnd = 0;
	DWORD eipStart = 0;
	DWORD eipEnd = 0;
	FStringAssignmentOperator_wchar_t_t FStringAssignmentOperator_wchar_t = nullptr;
	DrawTextWithIconsParams nameOverAvatarArgs;
	// 0x1a0 - has an FString there
	// 0x1ac - a dedicated length field
	BYTE* nameOverAvatarSecondArg = nullptr;
private:
	class PatchGuard {
	public:
		PatchGuard(void* addr, size_t size, bool includeThisModule);
		~PatchGuard();
		bool fail = false;
	private:
		void* addr = nullptr;
		size_t size = 0;
		DWORD oldProtect = 0;
	};
	struct PatchedPlace {
		std::vector<BYTE> origData;
		void* loc = nullptr;
	};
	bool patch(void* addr, void* newData, size_t size);
	bool unpatch(void* addr, void* origData, size_t size);
	bool freezeMainThread();
	bool freezeAllThreads();
	std::vector<HANDLE> suspendedThreads;
	bool suspendThread(DWORD threadId);
	std::vector<PatchedPlace> patchedPlaces;
	bool ensureThreadNotInRegion(HANDLE threadHandle, DWORD eipStart, DWORD eipEnd, bool includeThisModule);
	bool hooksStillRunning();
	int countThreadsInProcess();
};

extern Main mod;
