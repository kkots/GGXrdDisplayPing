#include "pch.h"
#include "sigscan.h"
#include <Psapi.h>
#include "logging.h"

Sig::Sig(const char* str) {
	unsigned long long accumulatedNibbles = 0;
	int nibbleCount = 0;
	const char* byteSpecificationPtr = str;
	bool nibbleUnknown[16] { false };
	while (true) {
		char currentChar = *byteSpecificationPtr;
		if (currentChar != ' ' && currentChar != '\0') {
			char currentNibble = 0;
			bool isUnknown = false;
			if (currentChar >= '0' && currentChar <= '9') {
				currentNibble = currentChar - '0';
			} else if (currentChar >= 'a' && currentChar <= 'f') {
				currentNibble = currentChar - 'a' + 10;
			} else if (currentChar >= 'A' && currentChar <= 'F') {
				currentNibble = currentChar - 'A' + 10;
			} else if (currentChar == '?') {
				isUnknown = true;
				hasWildcards = true;
			} else {
				LOG_ERROR("Wrong byte specification: %s", str)
				break;
			}
			nibbleUnknown[nibbleCount] = isUnknown;
			if ((nibbleCount % 2) == 1 && nibbleUnknown[nibbleCount] != nibbleUnknown[nibbleCount - 1]) {
				// Cannot mask only half a byte
				LOG_ERROR("Wrong byte specification: %s", str)
				break;
			}
			accumulatedNibbles = (accumulatedNibbles << 4) | currentNibble;
			++nibbleCount;
			if (nibbleCount > 16) {
				LOG_ERROR("Wrong byte specification: %s", str)
				break;
			}
		} else if (nibbleCount) {
			for (int i = 0; i < nibbleCount; i += 2) {
				sig.push_back(accumulatedNibbles & 0xff);
				mask.push_back(nibbleUnknown[i] ? '?' : 'x');
				accumulatedNibbles >>= 8;
			}
			nibbleCount = 0;
			if (currentChar == '\0') {
				break;
			}
		}
		++byteSpecificationPtr;
	}
	sig.push_back('\0');
	mask.push_back('\0');
}

#ifdef _DEBUG
const char* Sig::repr() const {
	
	if (mask.size() <= 1) return "<empty>";
	
	reprStr.clear();
	reprStr.reserve(
		(
			(mask.size() - 1)  // the last char is a null character, do not include it
			* 3  // we're going to have 2 characters per byte, + 1 space character
		)
		- 1  // omit the last space character
	);
	
	bool isFirst = true;
	const char* sigP = sig.data();
	const char* maskP = mask.data();
	while (*maskP != '\0') {
		
		if (!isFirst) {
			reprStr.push_back(' ');
		} else {
			isFirst = false;
		}
		
		BYTE sigChar = *(BYTE*)sigP;
		char maskChar = *maskP;
		if (maskChar == 'x') {
			for (int i = 0; i < 2; ++i) {
				BYTE nibble = (sigChar >> 4) & 0xf;
				char letter;
				if (nibble < 10) letter = '0' + nibble;
				else letter = 'a' + nibble - 10;
				reprStr.push_back(letter);
				sigChar <<= 4;
			}
		} else {
			reprStr.push_back('?');
			reprStr.push_back('?');
		}
		
		++sigP;
		++maskP;
	}
	
	return reprStr.c_str();
}
#endif

void Sig::replace(int offset, void* src, int size) {
	memcpy(sig.data() + offset, src, size);
	memset(mask.data() + offset, 'x', size);
}

void splitOutModuleName(const char* moduleAndSectionName, char* moduleName, size_t moduleNameBufSize, char* sectionName, size_t sectionNameBufSize) {
	bool foundColon = false;
	for (const char* c = moduleAndSectionName; *c != '\0'; ++c) {
		if (*c == ':') {
			foundColon = true;
		} else if (!foundColon) {
			if (moduleNameBufSize <= 1) {
				LOG_ERROR("Ran out of module name buffer splitting out module and section names out of %s\n", moduleAndSectionName)
				continue;
			}
			*moduleName = *c;
			++moduleName;
			--moduleNameBufSize;
		} else {
			if (sectionNameBufSize <= 1) {
				LOG_ERROR("Ran out of section name buffer splitting out module and section names out of %s\n", moduleAndSectionName)
				continue;
			}
			*sectionName = *c;
			++sectionName;
			--sectionNameBufSize;
		}
	}
	*moduleName = '\0';
	*sectionName = '\0';
}

bool getModuleBounds(const char* moduleAndSectionName, const char** start, const char** end) {
	char moduleName[256] { '\0' };
	char sectionName[16] { '\0' };
	splitOutModuleName(moduleAndSectionName, moduleName, _countof(moduleName), sectionName, _countof(sectionName));
	if (sectionName[0] == '\0') {
		strncpy_s(sectionName, ".text", 5);
	}
	return getModuleBounds(moduleName, sectionName, start, end);
}

bool getModuleBounds(const char* moduleName, const char* sectionName, const char** start, const char** end) {
	HMODULE module = GetModuleHandleA(moduleName);
	if (module == nullptr) {
		LOG_ERROR("Module not found: %s\n", moduleName)
		return false;
	}

	return getModuleBoundsHandle(module, sectionName, start, end);
}

bool getModuleBoundsHandle(HMODULE hModule, const char* sectionName, const char** start, const char** end) {
	MODULEINFO info;
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &info, sizeof(info))) return false;
	*start = (const char*)(info.lpBaseOfDll);
	*end = *start + info.SizeOfImage;
	if (strcmp(sectionName, "all") == 0) return true;
	const char* peHeaderStart = *start + *(DWORD*)(*start + 0x3C);
	unsigned short numberOfSections = *(unsigned short*)(peHeaderStart + 0x6);
	unsigned short optionalHeaderSize = *(unsigned short*)(peHeaderStart + 0x14);
	const char* optionalHeaderStart = peHeaderStart + 0x18;
	const Section* sections = (const Section*)(optionalHeaderStart + optionalHeaderSize);  // section headers immediately follow the optional header
	for (unsigned short i = 0; i < numberOfSections; ++i) {
		const Section& section = sections[i];
		if (strncmp(section.name, sectionName, 8) == 0) {
			*start = *start + section.relativeVirtualAddress;
			*end = *start + section.virtualSize;
			return true;
		}
	}
	LOG_ERROR("getModuleBoundsHandle failed to find %s section in a module.\n", sectionName)
	return false;
}

const char* sigscan(const char* moduleAndSectionName, const char* sig, const char* mask) {
	const char* start;
	const char* end;
	if (!getModuleBounds(moduleAndSectionName, &start, &end)) {
		return nullptr;
	}
	return sigscan(start, end, sig, mask);
}

const char* sigscan(const char* moduleAndSectionName, const Sig& sig) {
	const char* result;
	if (sig.hasWildcards) {
		result = sigscan(moduleAndSectionName, sig.sig.data(), sig.mask.data());
	} else {
		result = sigscanBoyerMooreHorspool(moduleAndSectionName, sig.sig.data(), sig.sig.size() - 1);
	}
	if (!result) LOG_ERROR("Failed to find sig: %s\n", sig.repr())
	return result;
}

const char* sigscan(const char* start, const char* end, const char* sig, const char* mask) {
	const char* lastScan = end - strlen(mask);
	for (const char* addr = start; addr <= lastScan; addr++) {
		for (size_t i = 0;; i++) {
			if (mask[i] == '\0')
				return addr;
			if (mask[i] != '?' && sig[i] != *(char*)(addr + i))
				break;
		}
	}
	
	return nullptr;
}

const char* sigscanBoyerMooreHorspool(const char* moduleAndSectionName, const char* sig, size_t sigLength) {
	const char* start;
	const char* end;
	if (!getModuleBounds(moduleAndSectionName, &start, &end)) {
		return nullptr;
	}
	return sigscanBoyerMooreHorspool(start, end, sig, sigLength);
}

const char* sigscanBoyerMooreHorspool(const char* start, const char* end, const char* sig, size_t sigLength) {
	
	// Boyer-Moore-Horspool substring search
	// A table containing, for each symbol in the alphabet, the number of characters that can safely be skipped
	size_t step[256];
	for (int i = 0; i < _countof(step); ++i) {
		step[i] = sigLength;
	}
	for (size_t i = 0; i < sigLength - 1; i++) {
		step[(BYTE)sig[i]] = sigLength - 1 - i;
	}
	
	BYTE pNext;
	end -= sigLength;
	for (const char* p = start; p <= end; p += step[pNext]) {
		int j = sigLength - 1;
		pNext = *(BYTE*)(p + j);
		if (sig[j] == (char)pNext) {
			for (--j; j >= 0; --j) {
				if (sig[j] != *(char*)(p + j)) {
					break;
				}
			}
			if (j < 0) {
				return p;
			}
		}
	}

	return nullptr;
}

uintptr_t findImportedFunction(const char* module, const char* dll, const char* function) {
	HMODULE hModule = GetModuleHandleA(module);
	if (!hModule) {
		LOG_ERROR("Couldn't find module %s.\n", module)
		return 0;
	}
	
	MODULEINFO info;
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &info, sizeof(info))) return false;
	uintptr_t base = (uintptr_t)(info.lpBaseOfDll);
	uintptr_t peHeaderStart = base + *(uintptr_t*)(base + 0x3C);  // PE file header start
	struct RvaAndSize {
		DWORD rva;
		DWORD size;
	};
	uintptr_t optionalHeaderStart = peHeaderStart + 0x18;
	DWORD sizeOfOptionalHeader = *(DWORD*)(peHeaderStart + 0x14);
	if (sizeOfOptionalHeader < 0x68 + 0x10) {
		LOG_ERROR("In module %s the optional header size is too small: %u.\n", module, sizeOfOptionalHeader)
		return 0;
	}
	DWORD numberOfRvaAndSizes = *(DWORD*)(optionalHeaderStart + 0x5c);
	if (numberOfRvaAndSizes < 2) {
		LOG_ERROR("In module %s the number of RvaAndSizes is < 2.\n", module)
		return 0;
	}
	const RvaAndSize* importsDataDirectoryRvaAndSize = (const RvaAndSize*)(optionalHeaderStart + 0x68);
	struct ImageImportDescriptor {
		DWORD ImportLookupTableRVA;  // The RVA of the import lookup table. This table contains a 2-byte ordinal, immediately followed by an in-place ASCII name for each import. (The name "Characteristics" is used in Winnt.h, but no longer describes this field.)
		DWORD TimeDateStamp;  // Always 0.
		DWORD ForwarderChain;  // Always 0.
		DWORD NameRVA;  // The RVA of an ASCII string that contains the name of the DLL.
		DWORD ImportAddressTableRVA;  // The RVA of the import address table. This table contains a pointer to a function, for each import. Until the image is bound, instead of pointers it holds the exact same RVAs as the import lookup table, pointing to an ordinal and a name.
	};
	DWORD importsSize = importsDataDirectoryRvaAndSize->size;  // in bytes
	const ImageImportDescriptor* importPtrNext = (const ImageImportDescriptor*)(base + importsDataDirectoryRvaAndSize->rva);
	for (; importsSize > 0; importsSize -= sizeof ImageImportDescriptor) {
		const ImageImportDescriptor* importPtr = importPtrNext++;
		if (!importPtr->ImportLookupTableRVA) break;
		const char* dllName = (const char*)(base + importPtr->NameRVA);
		if (_stricmp(dllName, dll) != 0) continue;
		void** funcPtr = (void**)(base + importPtr->ImportAddressTableRVA);
		DWORD* imageImportByNameRvaPtr = (DWORD*)(base + importPtr->ImportLookupTableRVA);
		struct ImageImportByName {
			short importIndex;  // if you know this index you can use it for lookup. Name is just convenience for programmers.
			char name[1];  // arbitrary length, zero-terminated ASCII string
		};
		for (; *imageImportByNameRvaPtr != 0; ++imageImportByNameRvaPtr) {
			const ImageImportByName* importByName = (const ImageImportByName*)(base + *imageImportByNameRvaPtr);
			if (strcmp(importByName->name, function) == 0) {
				return (uintptr_t)funcPtr;
			}
			++funcPtr;
		}
		LOG_ERROR("In module %s for imported DLL %s couldn't find imported function %s.\n", module, dll, function)
		return 0;
	}
	LOG_ERROR("In module %s couldn't find imported DLL %s.\n", module, dll)
	return 0;
}

int calculateRelativeCall(const void* callInstrAddr, const void* calledAddress) {
	return (int)calledAddress - ((int)callInstrAddr + 5);
}

const void* followRelativeCall(const void* callInstrAddr) {
	return (const void*)(
		(BYTE*)callInstrAddr + 5 + *(int*)((BYTE*)callInstrAddr + 1)
	);
}

const char* sigscanString(const char* moduleAndSectionName, const char* txt, size_t txtByteSize) {
	const char* result = sigscanBoyerMooreHorspool(moduleAndSectionName, txt, txtByteSize - 1);
	if (!result) LOG_ERROR("Failed to find %s string.\n", txt)
	return result;
}

const char* sigscanWithRelativeCalls(const char* start, const char* end, const char* sig, const char* mask, const std::vector<size_t>& relativeCalls) {
	const char* lastScan = end - strlen(mask);
	int relCallArIndex = 0;
	size_t relCallIndex = 0;
	int relCallOffset = 0;
	int relCallSigIndex = 0;
	bool inRelCall = false;
	for (const char* addr = start; addr <= lastScan; addr++) {
		inRelCall = false;
		if (relativeCalls.empty()) {
			relCallIndex = 0xFFFFFFFF;
		} else {
			relCallArIndex = 0;
			relCallIndex = relativeCalls.front();
		}
		for (size_t i = 0;; i++) {
			if (!inRelCall) {
				if (i == relCallIndex) {
					relCallSigIndex = 0;
					relCallOffset = calculateRelativeCall(addr + i, *(const void**)(sig + i + 1));
					inRelCall = true;
					if (relCallArIndex == relativeCalls.size() - 1) {
						relCallIndex = 0xFFFFFFFF;
					} else {
						++relCallArIndex;
						relCallIndex = relativeCalls[relCallArIndex];
					}
				}
				if (mask[i] == '\0')
					return addr;
				if (mask[i] != '?' && sig[i] != *(char*)(addr + i))
					break;
			} else {
				if (*(char*)(addr + i) != *((char*)&relCallOffset + relCallSigIndex)) {
					break;
				}
				++relCallSigIndex;
				if (relCallSigIndex == 4) {
					inRelCall = false;
				}
			}
		}
	}
	return nullptr;
}
