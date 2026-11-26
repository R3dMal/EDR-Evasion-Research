#pragma once
#include "common.h"

DWORD HashStringA(const char *str);
PVOID ResolveExportByHash(PVOID module_base, DWORD func_hash);
PVOID GetModuleByHash(DWORD module_hash);
PVOID GetFuncByHash(DWORD func_hash);
