#pragma once

#ifndef _DEBUG
#define LOG_ERROR(fmt, ...) {}
#else
void logError(const char* fmt, ...);
#define LOG_ERROR(fmt, ...) logError(fmt, __VA_ARGS__);
#endif
