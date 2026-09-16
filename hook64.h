#pragma once

typedef enum {
    HOOK_INVALID_MOD_NAME,
    HOOK_UNKNOWN_MOD,
    HOOK_NO_CAVE_FOUND,
    HOOK_INVALID_FUN_NAME,
    HOOK_INVALID_WRITEBACK,
    HOOK_UNKNOWN_FUN,
    HOOK_RELOAD_FAILED,
    HOOK_SUCCEED,
} hook_status;

typedef struct {
    const char* fun_name;
    void* detour;
    void** orginal;
} hook_detour_entry;

hook_status hook_module(char* module_name, hook_detour_entry detours[], int detour_count);

typedef enum {
    HOOK_RELOAD_FAILED_SNAPSHOT,
    HOOK_RELOAD_NO_MODULES,
    HOOK_RELOAD_SUCCEED,
} hook_reload_status;

hook_reload_status hook_reload(char* module_name);
