#include "pch.h"
#include <TlHelp32.h>
#include "Main.h"
#include "sigscan.h"
#include "logging.h"
#include "WError.h"
#include <algorithm>
#include <string>

Main mod;

// incremented and decremented atomically by all asm hooks
extern "C" DWORD hookCounter = 0;
extern "C" DWORD lastPing = 0;

// data members are accessed from Lobbies.asm
// functions are defined here, in this .cpp file, but called by Lobbies.asm
extern "C" DWORD pingToConnectionStrength1 = 0;
extern "C" DWORD orig_LobbyListRememberPing = 0;

extern "C" DWORD LobbyListDrawConnectionTierCall = 0;
extern "C" DWORD orig_LobbyListDrawConnectionTier = 0;
extern "C" void __cdecl printPingFromLobbyList(float x, float y);

extern "C" DWORD PlayerListCall = 0;
extern "C" DWORD orig_PlayerList = 0;

extern "C" DWORD PlayerListGetPing = 0;
extern "C" DWORD orig_GetConnectionStrength = 0;
extern "C" void __cdecl printPingFromPlayerList(float x, float y);

extern "C" DWORD orig_AvatarName = 0;
extern "C" void __cdecl rememberAvatarPlayerNameInLobby(void* args, void* secondArg);

extern "C" DWORD drawIcon = 0;
extern "C" DWORD orig_ConnectionTierIconInLobby = 0;
extern "C" void __cdecl printPingFromAvatarInLobby(DrawTextWithIconsParams* params);

extern "C" void __cdecl LobbyListRememberPing();  // declared in Lobbies.asm as _LobbyListRememberPing
extern "C" void __cdecl LobbyListDrawConnectionTier();  // as _LobbyListDrawConnectionTier
extern "C" void __cdecl PlayerListDrawConnectionTier();  // as _PlayerListDrawConnectionTier
extern "C" void __cdecl PlayerListGetPingHook();  // as _PlayerListGetPingHook
extern "C" void __cdecl AvatarPlayerNameInLobby();  // as _AvatarPlayerNameInLobby
extern "C" void __cdecl ConnectionTierIconInLobby();  // as _ConnectionTierIconInLobby


extern "C" drawTextWithIcons_t drawTextWithIcons = nullptr;

LONG NTAPI vectoredExceptionHandler(_EXCEPTION_POINTERS *ExceptionInfo);

bool Main::attach(HMODULE hModule) {
	
	if (!getModuleBoundsHandle(hModule, ".text", (const char**)&thisModuleStart, (const char**)&thisModuleEnd)) return false;
	
	if (!freezeMainThread()) return false;
	
	struct Cleanup {
		~Cleanup() {
			mod.unfreeze();
		}
	} cleanup;
	
	char* place;
	Sig sig;
	int offset;
	BYTE buf[7];
	
	place = (char*)sigscan("GuiltyGearXrd.exe:.text", Sig("8b 48 44 51 e8 ?? ?? ?? ?? 8b 4c 24 30 83 c4 04"));
	if (!place) return false;
	
	place += 4;
	// points to
	// 00ebf925 e8 b6 6c 17 00    CALL pingToConnectionStrength1
	
	pingToConnectionStrength1 = (DWORD)followRelativeCall(place);
	orig_LobbyListRememberPing = (DWORD)place + 5;
	offset = calculateRelativeCall(place, LobbyListRememberPing);
	
	buf[0] = 0xE9;  // relative JMP with 4-byte offset
	memcpy(buf + 1, &offset, 4);
	if (!patch(place, buf, 5)) return false;
	
	
	char* TrainingEtc_OneDamage = (char*)sigscan("GuiltyGearXrd.exe:.rdata", "TrainingEtc_OneDamage");
	if (!TrainingEtc_OneDamage) return false;
	sig = Sig("c7 40 28 ?? ?? ?? ?? e8");
	sig.replace(3, &TrainingEtc_OneDamage, 4);
	
	char* drawTextWithIconsCall = (char*)sigscan("GuiltyGearXrd.exe:.text", sig);
	if (!drawTextWithIconsCall) return false;
	drawTextWithIconsCall += 7;
	// points at
	// 00fcc317 e8 a4 b7 fd ff    CALL drawTextWithIcons
	drawTextWithIcons = (drawTextWithIcons_t)followRelativeCall(drawTextWithIconsCall);
	
	
	place = (char*)sigscan("GuiltyGearXrd.exe:.text", Sig("f3 0f 11 84 24 c8 02 00 00 89 94 24 ec 02 00 00 e8"));
	if (!place) return false;
	
	place += 16;
	// points to
	// 00ebe398 e8 93 21 ef ff    CALL FUN_00db0530
	
	LobbyListDrawConnectionTierCall = (DWORD)followRelativeCall(place);
	orig_LobbyListDrawConnectionTier = (DWORD)place + 5;
	offset = calculateRelativeCall(place, LobbyListDrawConnectionTier);
	buf[0] = 0xE9;  // relative JMP with 4-byte offset
	memcpy(buf + 1, &offset, 4);
	if (!patch(place, buf, 5)) return false;
	
	
	char* Net_Room_07 = (char*)sigscan("GuiltyGearXrd.exe:.rdata", L"Net_Room_07_%02d");
	if (!Net_Room_07) return false;
	buf[0] = 0x68;  // push
	memcpy(buf + 1, &Net_Room_07, 4);
	place = (char*)sigscan("GuiltyGearXrd.exe:.text", (const char*)buf, "xxxxx");
	if (!place) return false;
	
	place -= 13;
	// points to
	// 00e89b23 e8 f8 cf 1a 00    CALL getConnectionStrength
	
	char* getConnectionStrength = (char*)followRelativeCall(place);
	char* insideGetConnectionStrength = (char*)sigscan(getConnectionStrength, getConnectionStrength + 0x10, "\x50\xe8", "xx");
	if (!insideGetConnectionStrength) return false;
	++insideGetConnectionStrength;
	// points to
	// 01036b25 e8 56 8d f4 ff    CALL FUN_00f7f880
	
	
	PlayerListGetPing = (DWORD)followRelativeCall(insideGetConnectionStrength);
	orig_GetConnectionStrength = (DWORD)insideGetConnectionStrength + 5;
	offset = calculateRelativeCall(insideGetConnectionStrength, PlayerListGetPingHook);
	buf[0] = 0xE9;  // JMP with 32-byte offset
	memcpy(buf + 1, &offset, 4);
	if (!patch(insideGetConnectionStrength, buf, 5)) return false;
	
	place += 13;
	place += 0x75;
	// points to
	// 00e89ba5 e8 86 69 f2 ff    CALL FUN_00db0530
	PlayerListCall = (DWORD)followRelativeCall(place);
	orig_PlayerList = (DWORD)place + 5;
	offset = calculateRelativeCall(place, PlayerListDrawConnectionTier);
	buf[0] = 0xE9;  // JMP with 32-byte offset
	memcpy(buf + 1, &offset, 4);
	if (!patch(place, buf, 5)) return false;
	
	
	place = (char*)sigscan("GuiltyGearXrd.exe:.rdata", L"ClassDefaultObject");
	if (!place) return false;
	sig = Sig("68 ?? ?? ?? ??");
	sig.replace(1, &place, 4);
	place = (char*)sigscan("GuiltyGearXrd.exe:.text", sig);
	if (!place) return false;
	FStringAssignmentOperator_wchar_t = (FStringAssignmentOperator_wchar_t_t)followRelativeCall(place + 9);
	
	
	const char* rdataStart;
	const char* rdataEnd;
	if (!getModuleBounds("GuiltyGearXrd.exe:.rdata", &rdataStart, &rdataEnd)) return false;
	char* QOS = (char*)sigscan(rdataStart, rdataEnd, "QOS%d", "xxxxxx");
	if (!QOS) return false;
	QOS = (char*)sigscan(QOS + 5, rdataEnd, "QOS%d", "xxxxx");  // find the second 
	if (!QOS) return false;
	
	sig = Sig("68 ?? ?? ?? ??");
	sig.replace(1, &QOS, 4);
	place = (char*)sigscan("GuiltyGearXrd.exe:.text", sig);
	if (!place) return false;
	sig = Sig("89 10 e8 ?? ?? ?? ?? 83 c4 14");
	place = (char*)sigscan(place + 1, place + 0xb0, sig.sig.data(), sig.mask.data());
	if (!place) return false;
	place += 11;
	// points to
	// 00e9734f e8 cc 49 f1 ff    CALL drawIcon
	orig_ConnectionTierIconInLobby = (DWORD)place + 5;
	drawIcon = (DWORD)followRelativeCall(place);
	offset = calculateRelativeCall(place, ConnectionTierIconInLobby);
	buf[0] = 0xE9;  // JMP with 32-byte offset
	memcpy(buf + 1, &offset, 4);
	if (!patch(place, buf, 5)) return false;

	
	place = (char*)sigscan("GuiltyGearXrd.exe:.text", Sig("c7 86 f4 00 00 00 e0 00 00 40 f3 0f 11 96 00 01 00 00"));
	if (!place) return false;
	sig = Sig("56 e8 ?? ?? ?? ??");
	void* ptr = (void*)drawTextWithIcons;
	sig.replace(2, &ptr, 4);
	place = (char*)sigscanWithRelativeCalls(place + 17, place + 0x1b0, sig.sig.data(), sig.mask.data(), { 1 });
	if (!place) return false;
	++place;
	// points to
	//                            draws player name on top of an avatar inside a lobby
    // 00e90cc9 e8 f2 6d 11 00    CALL drawTextWithIcons
	
	orig_AvatarName = (DWORD)place + 5;
	buf[0] = 0xE9;  // JMP with 32-byte offset
	offset = calculateRelativeCall(place, AvatarPlayerNameInLobby);
	memcpy(buf + 1, &offset, 4);
	if (!patch(place, buf, 5)) return false;
	
	return true;
}

bool Main::detach() {
	
	if (countThreadsInProcess() == 1) hookCounter = 0;
	
	if (!freezeMainThread()) return false;
	
	for (PatchedPlace& place : patchedPlaces) {
		unpatch(place.loc, place.origData.data(), place.origData.size());  // nothing we can do in case of error
	}
	patchedPlaces.clear();
	mod.unfreeze();
	
	do {
		Sleep(100);
	} while (hooksStillRunning());
	
	return true;
}

bool Main::patch(void* addr, void* newData, size_t size) {
	PatchGuard guard(addr, size, false);
	if (guard.fail) return false;
	
	patchedPlaces.emplace_back();
	PatchedPlace& newPatch = patchedPlaces.back();
	newPatch.loc = addr;
	newPatch.origData.resize(size);
	memcpy(newPatch.origData.data(), addr, size);
	memcpy(addr, newData, size);
	
	return true;
}

bool Main::unpatch(void* addr, void* origData, size_t size) {
	PatchGuard guard(addr, size, true);
	if (guard.fail) return false;
	
	memcpy(addr, origData, size);
	
	return true;
	
}

bool Main::freezeMainThread() {
	HWND foundGgWindow = FindWindowW(L"LaunchUnrealUWindowsClient", L"Guilty Gear Xrd -REVELATOR-");
	if (!foundGgWindow) return freezeAllThreads();
	DWORD windsProcId;
	DWORD threadId = GetWindowThreadProcessId(foundGgWindow, &windsProcId);
	if (!threadId) return freezeAllThreads();
	if (threadId == GetCurrentThreadId()) return true;
	suspendThread(threadId);
	return true;
}

bool Main::suspendThread(DWORD threadId) {
	HANDLE hThread = OpenThread(
			THREAD_SUSPEND_RESUME
				| THREAD_GET_CONTEXT
				| THREAD_SET_CONTEXT
				| SYNCHRONIZE
				| THREAD_QUERY_INFORMATION,
			FALSE, threadId);
	if (hThread == NULL || hThread == INVALID_HANDLE_VALUE) {
		WinError winErr;
		LOG_ERROR("Failed to open thread 0x%x: Error code 0x%x %ls\n", threadId, winErr.code, winErr.message)
		return false;
	}
	if (SuspendThread(hThread) == (DWORD)-1) {
		WinError winErr;
		LOG_ERROR("Failed to suspend thread 0x%x: Error code 0x%x %ls\n", threadId, winErr.code, winErr.message)
		CloseHandle(hThread);
		return false;
	}
	suspendedThreads.push_back(hThread);  // error is fine
	return true;
}

bool Main::freezeAllThreads() {
	DWORD currentThreadId = GetCurrentThreadId();
	DWORD currentProcessId = GetCurrentProcessId();
	THREADENTRY32 th32{0};
	th32.dwSize = sizeof(THREADENTRY32);
	bool foundNotYetEnumeratedThread;
	std::vector<DWORD> enumeratedThreads;
	do {
		foundNotYetEnumeratedThread = false;
		
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!hSnapshot || hSnapshot == INVALID_HANDLE_VALUE) {
			WinError winErr;
			LOG_ERROR("Error in CreateToolhelp32Snapshot: Error code 0x%x %ls\n", winErr.code, winErr.message)
			return false;
		}
		
		if (!Thread32First(hSnapshot, &th32)) {
			WinError winErr;
			LOG_ERROR("Error in Thread32First: Error code 0x%x %ls\n", winErr.code, winErr.message)
			CloseHandle(hSnapshot);
			return false;
		}
		
		while (true) {
			if (th32.th32OwnerProcessID == currentProcessId
					&& th32.th32ThreadID != currentThreadId
					&& std::find(enumeratedThreads.begin(), enumeratedThreads.end(), th32.th32ThreadID) == enumeratedThreads.end()) {
				enumeratedThreads.push_back(th32.th32ThreadID);
				suspendThread(th32.th32ThreadID);  // error is fine
				foundNotYetEnumeratedThread = true;
			}
			if (!Thread32Next(hSnapshot, &th32)) {
				WinError winErr;
				if (winErr.code != ERROR_NO_MORE_FILES) {
					LOG_ERROR("Error in Thread32Next: Error code 0x%x %ls\n", winErr.code, winErr.message)
					CloseHandle(hSnapshot);
					return false;
				}
				break;
			}
		}
		CloseHandle(hSnapshot);
	} while (foundNotYetEnumeratedThread);
	return true;
}

bool Main::unfreeze() {
	for (HANDLE hndl : suspendedThreads) {
		ResumeThread(hndl);
	}
	suspendedThreads.clear();
	return true;
}

// No one knows where we are, how we got here or what is even happening
LONG NTAPI vectoredExceptionHandler(_EXCEPTION_POINTERS *ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP
			&& GetCurrentThreadId() == mod.threadBeingSteppedId) {
		if (mod.eipIsIn(ExceptionInfo->ContextRecord->Eip)) {
			Main::setTrapFlag(&ExceptionInfo->ContextRecord->EFlags);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		// Common sense: Is it safe to remove this exception handler from within the handler? What would happen after this function exits?
		// Me: I don't know but I'll put this here of all places
		RemoveVectoredExceptionHandler(mod.exceptionHandle);
		// Microsoft: The handler should not call functions that acquire synchronization objects or allocate memory, because this can cause problems.
		// Me: Naah
		SetEvent(mod.threadFinishedStepping);
		// People: Can a thread suspend itself? Is that even possible??
		// Me: Let's find out
		SuspendThread(GetCurrentThread());
		// Some guy: My program is stuck in an infinite exception loop unless I increment EIP
		// Me: Works on my machine
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

// This approach can cause deadlocks if this thread attempts to take a mutex occupied by another thread which is also frozen
bool Main::ensureThreadNotInRegion(HANDLE threadHandle, DWORD eipStart, DWORD eipEnd, bool includeThisModule) {
	
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	
	if (!GetThreadContext(threadHandle, &ctx)) {
		WinError winErr;
		LOG_ERROR("GetThreadContext failed: Error code 0x%x %ls\n", winErr.code, winErr.message)
		return false;
	}
	
	this->eipStart = eipStart;
	this->eipEnd = eipEnd;
	this->includeThisModule = includeThisModule;
	
	if (!eipIsIn(ctx.Eip)) return true;
	
	setTrapFlag(&ctx.EFlags);
	if (!SetThreadContext(threadHandle, &ctx)) {
		WinError winErr;
		LOG_ERROR("SetThreadContext failed: Error code 0x%x %ls\n", winErr.code, winErr.message)
		return false;
	}
	if (!threadFinishedStepping) {
		threadFinishedStepping = CreateEventW(NULL, FALSE, FALSE, NULL);
		if (!threadFinishedStepping) {
			WinError winErr;
			LOG_ERROR("CreateEventW failed: Error code 0x%x %ls\n", winErr.code, winErr.message)
			return false;
		}
	}
	threadBeingSteppedId = GetThreadId(threadHandle);
	if (threadBeingSteppedId == 0) {
		WinError winErr;
		LOG_ERROR("GetThreadId failed: Error code 0x%x %ls\n", winErr.code, winErr.message)
		return false;
	}
	exceptionHandle = AddVectoredExceptionHandler(1, vectoredExceptionHandler);
	if (exceptionHandle == NULL) {
		WinError winErr;
		LOG_ERROR("AddVectoredExceptionHandler failed: Error code 0x%x %ls\n", winErr.code, winErr.message)
		return false;
	}
	if (!ResumeThread(threadHandle)) {
		WinError winErr;
		LOG_ERROR("ResumeThread failed: Error code 0x%x %ls\n", winErr.code, winErr.message)
		return false;
	}
	HANDLE handles[2] { threadFinishedStepping, threadHandle };
	DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
	if (waitResult == WAIT_FAILED) {
		WinError winErr;
		LOG_ERROR("WaitForMultipleObjects failed: Error code 0x%x %ls\n", winErr.code, winErr.message)
	}
	if (waitResult != WAIT_OBJECT_0) {
		RemoveVectoredExceptionHandler(mod.exceptionHandle);
	}
	if (waitResult == WAIT_FAILED) return false;
	return true;
}

Main::PatchGuard::PatchGuard(void* addr, size_t size, bool includeThisModule) : addr(addr), size(size) {
	if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		WinError winErr;
		LOG_ERROR("VirtualProtect failed at address %p, size %zu: Error code 0x%x %ls\n", addr, size, winErr.code, winErr.message)
		fail = true;
		return;
	}
	
	for (HANDLE hndl : mod.suspendedThreads) {
		if (!mod.ensureThreadNotInRegion(hndl, (DWORD)addr, (DWORD)addr + size, includeThisModule)) {
			fail = true;
			return;
		}
	}
}

Main::PatchGuard::~PatchGuard() {
	if (fail) return;
	
	DWORD unused;
	if (!VirtualProtect(addr, size, oldProtect, &unused)) {
		WinError winErr;
		LOG_ERROR("VirtualProtect failed at address %p, size %zu: Error code 0x%x %ls\n", addr, size, winErr.code, winErr.message)
		fail = true;
		return;
	}
	FlushInstructionCache(GetCurrentProcess(), addr, size);
}

bool Main::eipIsIn(DWORD eip) {
	if (eip > eipStart && eip < eipEnd) return true;
	if (includeThisModule && (
		hookCounter > 0
		|| eip >= thisModuleStart && eip < thisModuleEnd
	)) return true;
	return false;
}

bool Main::hooksStillRunning() {
	if (!freezeMainThread()) return false;
	
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	
	eipStart = 0;
	eipEnd = 0;
	includeThisModule = true;
	
	bool stillRunning = false;
	for (HANDLE hndl : suspendedThreads) {
		
		if (!GetThreadContext(hndl, &ctx)) {
			WinError winErr;
			LOG_ERROR("GetThreadContext failed: Error code 0x%x %ls\n", winErr.code, winErr.message)
			return false;
		}
		
		if (eipIsIn(ctx.Eip)) {
			stillRunning = true;
			break;
		}
	}
	
	unfreeze();
	return stillRunning;
}

extern "C" void __cdecl printPingFromLobbyList(float x, float y) {
	char strbuf[10] { '\0' };
	sprintf_s(strbuf, "%d", lastPing);
	
	DrawTextWithIconsParams s;
	s.field159_0x100 = 36.0;
	s.layer = 0xb1;
	s.field160_0x104 = -1.0;
	s.field4_0x10 = -1.0;
	s.field155_0xf0 = 1;
	s.field157_0xf8 = -1;
	s.field158_0xfc = -1;
	s.field161_0x108 = 0;
	s.field162_0x10c = 0;
	s.field163_0x110 = -1;
	s.field164_0x114 = 0;
	s.field165_0x118 = 0;
	s.field166_0x11c = -1;
	s.outlineColor = 0xff000000;
	s.flags2 = 0xff000000;
	s.x = x + 24.F;
	s.y = y - 10.F;
	s.alignment = ALIGN_CENTER;
	s.text = strbuf;
	s.field156_0xf4 = 0x210;
	s.tint = 0xFFFFFF00;
	drawTextWithIcons(&s,0x0,1,4,0,0);
	
}

extern "C" void __cdecl printPingFromPlayerList(float x, float y) {
	char strbuf[10] { '\0' };
	sprintf_s(strbuf, "%d", lastPing);
	
	DrawTextWithIconsParams s;
	s.field159_0x100 = 36.0;
	s.layer = 0xb2;
	s.field160_0x104 = -1.0;
	s.field4_0x10 = -1.0;
	s.field155_0xf0 = 1;
	s.field157_0xf8 = -1;
	s.field158_0xfc = -1;
	s.field161_0x108 = 0;
	s.field162_0x10c = 0;
	s.field163_0x110 = -1;
	s.field164_0x114 = 0;
	s.field165_0x118 = 0;
	s.field166_0x11c = -1;
	s.outlineColor = 0xff000000;
	s.flags2 = 0xff000000;
	s.x = x + 14.F;
	s.y = y - 10.F;
	s.alignment = ALIGN_CENTER;
	s.text = strbuf;
	s.field156_0xf4 = 0x210;
	s.tint = 0xFFFFFF00;
	s.scaleX = 0.8F;
	s.scaleY = 0.8F;
	drawTextWithIcons(&s,0x0,1,4,0,0);
}

int Main::countThreadsInProcess() {
	int result = 0;
	
	THREADENTRY32 th32{0};
	th32.dwSize = sizeof(THREADENTRY32);
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnapshot || hSnapshot == INVALID_HANDLE_VALUE) {
		WinError winErr;
		LOG_ERROR("Error in CreateToolhelp32Snapshot: Error code 0x%x %ls\n", winErr.code, winErr.message)
		return result;
	}
	
	if (!Thread32First(hSnapshot, &th32)) {
		WinError winErr;
		LOG_ERROR("Error in Thread32First: Error code 0x%x %ls\n", winErr.code, winErr.message)
		CloseHandle(hSnapshot);
		return result;
	}
	
	DWORD currentProcessId = GetCurrentProcessId();
	
	while (true) {
		if (th32.th32OwnerProcessID == currentProcessId) {
			++result;
		}
		if (!Thread32Next(hSnapshot, &th32)) {
			WinError winErr;
			if (winErr.code != ERROR_NO_MORE_FILES) {
				LOG_ERROR("Error in Thread32Next: Error code 0x%x %ls\n", winErr.code, winErr.message)
			}
			break;
		}
	}
	CloseHandle(hSnapshot);
	return result;
}

extern "C" void __cdecl rememberAvatarPlayerNameInLobby(void* args, void* secondArg) {
	BYTE* secondArgCast = (BYTE*)secondArg;
	
	memcpy(&mod.nameOverAvatarArgs, args, sizeof DrawTextWithIconsParams);
	mod.nameOverAvatarSecondArg = (BYTE*)secondArg;
	
}

extern "C" void __cdecl printPingFromAvatarInLobby(DrawTextWithIconsParams* params) {
	
	wchar_t strbuf[10] { L'\0' };
	swprintf_s(strbuf, L"%d", lastPing);
	
	char strbuf_char[10] { '\0' };
	sprintf_s(strbuf_char, "%d", lastPing);
	
	BYTE* secondArg = mod.nameOverAvatarSecondArg;
	
	int oldLength = *(int*)(secondArg + 0x1ac);
	int fStringSize = *(int*)(secondArg + 0x1a4);
	std::wstring oldBuf;
	if (fStringSize != 0) {
		oldBuf.resize(fStringSize - 1, L'\0');
		memcpy(&oldBuf.front(), *(const wchar_t**)(secondArg + 0x1a0), oldBuf.size() * sizeof (wchar_t));
	}
	mod.FStringAssignmentOperator_wchar_t((FString*)(secondArg + 0x1a0), strbuf);
	int newFStringSize = *(int*)(secondArg + 0x1a4);
	*(int*)(secondArg + 0x1ac) = newFStringSize == 0 ? 0 : newFStringSize - 1;
	
	DrawTextWithIconsParams& s = mod.nameOverAvatarArgs;
	s.tint = 0xffffff00;
	// this is the exact top left corner of the connection tier icon
	s.x = params->x;
	s.y = params->y + params->scaleY * 26.F;
	// under the connection tier icon
	s.alignment = ALIGN_LEFT;
	s.x -= 2.F;
	s.y += params->scaleY * 26.F;
	s.scaleX *= 0.85F;
	s.scaleY *= 0.85F;
	s.text = strbuf_char;
	s.field159_0x100 *= 0.85F;
	drawTextWithIcons(&s,secondArg,1,4,0,0);
	
	*(int*)(secondArg + 0x1ac) = oldLength;
	if (oldBuf.empty()) {
		mod.FStringAssignmentOperator_wchar_t((FString*)(secondArg + 0x1a0), L"");
	} else {
		mod.FStringAssignmentOperator_wchar_t((FString*)(secondArg + 0x1a0), oldBuf.c_str());
	}
}
