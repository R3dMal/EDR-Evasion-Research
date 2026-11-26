#pragma once
#include "common.h"

/*
 * PPID Spoofing
 *
 * Creates a new process with a spoofed parent (e.g., svchost.exe, explorer.exe).
 * Uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to set the parent.
 * The new process looks like a legitimate child of a system process.
 */

BOOL SpawnWithSpoofedParent(const char *exe_path, const char *parent_name, PPROCESS_INFORMATION pi);
