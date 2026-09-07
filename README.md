# hook64

singe file eat hook impl for x64 windows.

## - usage

```
#include "hook64.h"

hook_detour_entry detours[] = {
    {"NtCreateFile", NtCreateFileHook, (void**)&OriginalNtCreateFile},
    {"NtOpenFile", NtOpenFileHook, (void**)&OriginalNtOpenFile},
    {"NtDeleteFile", NtDeleteFileHook, (void**)&OriginalNtDeleteFile},
    {"NtSetInformationFile", NtSetInformationFileHook, (void**)&OriginalNtSetInformationFile},
    {"NtQueryAttributesFile", NtQueryAttributesFileHook, (void**)&OriginalNtQueryAttributesFile},
    {"NtQueryFullAttributesFile", NtQueryFullAttributesFileHook, (void**)&OriginalNtQueryFullAttributesFile},
    {"NtQueryDirectoryFile", NtQueryDirectoryFileHook, (void**)&OriginalNtQueryDirectoryFile},
    {"NtQueryDirectoryFileEx", NtQueryDirectoryFileExHook, (void**)&OriginalNtQueryDirectoryFileEx},
};

switch (hook_module(L"ntdll.dll", detours, sizeof(detours) / sizeof(hook_detour_entry))) {
    case HOOK_SUCCEED:
    case HOOK_INVALID_MOD_NAME:
    case HOOK_UNKNOWN_MOD:
    case HOOK_NO_CAVE_FOUND:
    case HOOK_INVALID_FUN_NAME:
    case HOOK_UNKNOWN_FUN:
    case HOOK_INVALID_WRITEBACK:
        break;
}
```
