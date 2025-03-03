#pragma once
#include <vector>
#ifdef _DEBUG
#include <string>
#endif

struct Section {
	
    char name[8];
	
	// The size in terms of virtual address space.
    DWORD virtualSize = 0;
    
	// RVA. Virtual address offset relative to the virtual address start of the entire .exe.
	// So let's say the whole .exe starts at 0x400000 and RVA is 0x400.
	// That means the non-relative VA is 0x400000 + RVA = 0x400400.
	// Note that the .exe, although it does specify a base virtual address for itself on the disk,
	// may actually be loaded anywhere in the RAM once it's launched, and that RAM location will
	// become its base virtual address.
    DWORD relativeVirtualAddress = 0;
    
	// Size of this section's data on disk in the file.
    DWORD rawSize = 0;
    
	// Actual position of the start of this section's data within the file.
    DWORD rawAddress = 0;
    
    char padding[16];
    
};

class Sig {
public:
	// str is a byte specification of the format "00 8f 1e ??". ?? means unknown byte.
	// Converts a "00 8f 1e ??" string into two vectors:
	// sig vector will contain bytes '00 8f 1e' for the first 3 bytes and 00 for every ?? byte.
	// sig vector will be terminated with an extra 0 byte.
	// mask vector will contain an 'x' character for every non-?? byte and a '?' character for every ?? byte.
	// mask vector will be terminated with an extra 0 byte.
	Sig() = default;
	Sig(const Sig& sig) = default;
	Sig(Sig&& sig) = default;
	Sig& operator=(const Sig& sig) = default;
	Sig& operator=(Sig&& sig) = default;
	explicit Sig(const char* str);
	std::vector<char> sig;
	std::vector<char> mask;
	bool hasWildcards = false;
	void replace(int offset, void* src, int size);
	#ifdef _DEBUG
	mutable std::string reprStr;
	const char* repr() const;
	#endif
};

/// <summary>
/// Given a string of the format MODULE_NAME:SECTION_NAME (for ex. GuiltyGearXrd.exe:.text),
/// split out the module name and the section name.
/// 
/// The section name is optional, and if it's present, the : may be written as ::
/// </summary>
/// <param name="moduleAndSectionName">A string of the format MODULE_NAME:SECTION_NAME (for ex. GuiltyGearXrd.exe:.text)</param>
/// <param name="moduleName">The output module name.</param>
/// <param name="sectionName">The output section name. If it was not present, "all" is returned.</param>
void splitOutModuleName(const char* moduleAndSectionName, char* moduleName, size_t moduleNameBufSize, char* sectionName, size_t sectionNameBufSize);

bool getModuleBounds(const char* moduleAndSectionName, const char** start, const char** end);

bool getModuleBounds(const char* moduleName, const char* sectionName, const char** start, const char** end);

bool getModuleBoundsHandle(HMODULE hModule, const char* sectionName, const char** start, const char** end);

/// <param name="moduleName">Includes module name and, optionally, section name, in this format: GuiltyGearXrd.exe:.text</param>
/// <param name="sig">The signature to search.</param>
/// <param name="mask">The mask that must be the same length as the sig.
/// Only two symbols are allowed in the mask:
///  'x' symbol means the corresponding byte from the sig must match the data being searched;
///  '?' symbol means the corresponding byte from the sig must be skipped and does not matter.
///  This is like a wildcard.
///  The mask must end with a '\0' (null) character.</param>
/// <returns>nullptr if the signature is not found. The exact address where the signature starts, if found.</returns>
const char* sigscan(const char* moduleAndSectionName, const char* sig, const char* mask);

const char* sigscan(const char* moduleAndSectionName, const Sig& sig);

const char* sigscan(const char* start, const char* end, const char* sig, const char* mask);

const char* sigscanBoyerMooreHorspool(const char* moduleAndSectionName, const char* sig, size_t sigLength);

const char* sigscanBoyerMooreHorspool(const char* start, const char* end, const char* sig, size_t sigLength);

const char* sigscanString(const char* moduleAndSectionName, const char* txt, size_t txtByteSize);

template <size_t size>
inline const char* sigscan(const char* moduleAndSectionName, const char(&txt)[size]) {
	return sigscanString(moduleAndSectionName, txt, size);
}

template <size_t size>
inline const char* sigscan(const char* moduleAndSectionName, const wchar_t(&txt)[size]) {
	return sigscanString(moduleAndSectionName, (const char*)txt, size * sizeof (wchar_t) - 1);
}

/// <summary>
/// Finds the address which holds a pointer to a function with the given name imported from the given DLL.
/// For example, searching USER32.DLL, GetKeyState would return a non-0 value on successful find, and
/// if you cast that value to a short (__stdcall**)(int) and dereference it, you would get a pointer to
/// GetKeyState that you can call. Or swap out for hooks.
/// 
/// This function is useless because the calls to imported functions are relative
/// and even then they call thunk functions (a thunk function is a function consisting only
/// of a jump instruction to some other function).
/// </summary>
/// <param name="module">Type "GuiltyGearXrd.exe" here.</param>
/// <param name="dll">Include ".DLL" in the DLL's name here. Case-insensitive.</param>
/// <param name="function">The name of the function. Case-sensitive.</param>
/// <returns>The address which holds a pointer to a function. 0 if not found.</returns>
uintptr_t findImportedFunction(const char* module, const char* dll, const char* function);

int calculateRelativeCall(const void* callInstrAddr, const void* calledAddress);
const void* followRelativeCall(const void* callInstrAddr);

// Specify absolute addresses of functions in sig in places where relative offsets should be.
// In relativeCalls, specify the index numbers where starts of call instructions are.
// Absolute addresses will be converted to offsets automatically.
const char* sigscanWithRelativeCalls(const char* start, const char* end, const char* sig, const char* mask, const std::vector<size_t>& relativeCalls);
