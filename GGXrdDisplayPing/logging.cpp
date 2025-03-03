#include "pch.h"
#include <stdio.h>

#ifdef _DEBUG
char strbuf[1024] { '\0' };

void logError(const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vsnprintf(strbuf, sizeof strbuf, fmt, args);
	va_end(args);
	MessageBoxA(NULL, strbuf, PROJECT_NAME, MB_OK);
}
#endif
