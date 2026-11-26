#pragma once
#include "common.h"

/* Patch EtwEventWrite to silence ETW-based EDR telemetry */
BOOL PatchETW(void);

/* Patch AmsiScanBuffer to bypass AMSI scanning */
BOOL PatchAMSI(void);
