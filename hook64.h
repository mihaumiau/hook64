#pragma once

typedef enum {
    HOOK_SUCCEED,
    HOOK_INVALID_MOD_NAME,
    HOOK_UNKNOWN_MOD,
    HOOK_NO_CAVE_FOUND,
    HOOK_INVALID_FUN_NAME,
    HOOK_INVALID_WRITEBACK,
    HOOK_UNKNOWN_FUN
} hook_status;

typedef struct {
    const char* fun_name;
    void* detour;
    void** orginal;
} hook_detour_entry;

hook_status hook_module(unsigned short* module_name, hook_detour_entry detours[], int detour_count);
