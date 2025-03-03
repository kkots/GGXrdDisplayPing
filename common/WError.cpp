#include "pch.h"
#include "WError.h"

WinError::~WinError() {
	if (message) LocalFree(message);
}
WinError::WinError() {
	code = GetLastError();
	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)(&message),
		0, NULL);
}
