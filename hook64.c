#include "../include/hook.h"

#define WIN32_LEAN_AND_MEAN

#include <windows.h>

char jumper[] = {
    0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x50,
    0xC3,
    0xCC, 0xCC, 0xCC, 0xCC
};

hook_status hook_module(char* module_name, hook_detour_entry detours[], int detour_count) {
    if (!module_name) {
        return HOOK_INVALID_MOD_NAME;
    }

    void* module = GetModuleHandleA(module_name);

    if (!module) {
        return HOOK_UNKNOWN_MOD;
    }

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((char*)module + dos_header->e_lfanew);

    IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)((char*)nt_headers + sizeof(IMAGE_NT_HEADERS));

    void* code_cave = NULL;

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (section_header[i].Misc.VirtualSize - section_header[i].SizeOfRawData >= detour_count * sizeof(jumper)) {
                code_cave = (char*)module + section_header[i].VirtualAddress + section_header[i].SizeOfRawData;

                DWORD header_protect = 0;

                VirtualProtect(&section_header[i].SizeOfRawData, sizeof(DWORD), PAGE_READWRITE, &header_protect);

                section_header[i].SizeOfRawData += detour_count * sizeof(jumper);

                VirtualProtect(&section_header[i].SizeOfRawData, sizeof(DWORD), header_protect, &header_protect);

                break;
            }
        }
    }

    if (!code_cave) {
        return HOOK_NO_CAVE_FOUND;
    }

    DWORD cave_protect = 0;

    VirtualProtect(code_cave, detour_count * sizeof(jumper), PAGE_EXECUTE_READWRITE, &cave_protect);

    for (int detour_index = 0; detour_index < detour_count; detour_index++) {
        if (!detours[detour_index].fun_name) {
            return HOOK_INVALID_FUN_NAME;
        }

        *(void**)(jumper + 2) = detours[detour_index].detour;

        memcpy((char*)code_cave + detour_index * sizeof(jumper), jumper, sizeof(jumper));

        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
        IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((char*)module + dos_header->e_lfanew);

        IMAGE_DATA_DIRECTORY data_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((char*)module + data_dir.VirtualAddress);

        DWORD* names = (DWORD*)((char*)module + exports->AddressOfNames);
        WORD* ordinals = (WORD*)((char*)module + exports->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)((char*)module + exports->AddressOfFunctions);

        int found = 0;

        for (DWORD new_offset = (char*)code_cave - (char*)module + detour_index * sizeof(jumper), i = 0; i < exports->NumberOfNames; i++) {
            if (strcmp((char*)((char*)module + names[i]), detours[detour_index].fun_name) == 0) {
                if (detours[detour_index].orginal) {
                    *detours[detour_index].orginal = (char*)module + functions[ordinals[i]];
                } else {
                    return HOOK_INVALID_WRITEBACK;
                }

                DWORD eat_protect = 0;

                VirtualProtect(&functions[ordinals[i]], sizeof(DWORD), PAGE_READWRITE, &eat_protect);

                functions[ordinals[i]] = new_offset;

                VirtualProtect(&functions[ordinals[i]], sizeof(DWORD), eat_protect, &eat_protect);

                found = 1;
                break;
            }
        }

        if (!found) {
            return HOOK_UNKNOWN_FUN;
        }
    }

    VirtualProtect(code_cave, detour_count * sizeof(jumper), cave_protect, &cave_protect);

    return HOOK_SUCCEED;
}

hook_reload_status hook_reload(char* module_name) {
    HANDLE module_snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId()
    );

    if (!module_snapshot) {
        return HOOK_RELOAD_FAILED_SNAPSHOT;
    }

    MODULEENTRY32 module_entry = {};

    module_entry.dwSize = sizeof(module_entry);

    if (!Module32First(module_snapshot, &module_entry)) {
        return HOOK_RELOAD_NO_MODULES;
    }

    HMODULE module = getModuleHandleA(module_name);

    do {
        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_entry.hModule;
        IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((char*)module_entry.hModule + dos_header->e_lfanew);

        IMAGE_DATA_DIRECTORY data_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (!data_dir.VirtualAddress) {
            continue;
        }

        IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)((char*)module_entry.hModule + data_dir.VirtualAddress);

        for (; import_desc->Name != 0; import_desc++) {
            if (stricmp((char*)module_entry.hModule + import_desc->Name, module_name) == 0) {
                if (import_desc->OriginalFirstThunk == 0) {
                    continue;
                }

                IMAGE_THUNK_DATA* original_first_thunk = (IMAGE_THUNK_DATA*)((char*)module_entry.hModule + import_desc->OriginalFirstThunk);
                IMAGE_THUNK_DATA* first_thunk = (IMAGE_THUNK_DATA*)((char*)module_entry.hModule + import_desc->FirstThunk);

                SIZE_T thunk_size = 0;

                for (IMAGE_THUNK_DATA* current_thunk = original_first_thunk; current_thunk->u1.AddressOfData != 0; current_thunk++, thunk_size += sizeof(IMAGE_THUNK_DATA));

                DWORD iat_protect = 0;

                if (!VirtualProtect(first_thunk, thunk_size, PAGE_EXECUTE_READWRITE, &iat_protect)) {
                    continue;
                }

                for (; original_first_thunk->u1.AddressOfData != 0; original_first_thunk++, first_thunk++) {
                    if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                        first_thunk->u1.Function = (ULONG_PTR)GetProcAddress(module, MAKEINTRESOURCEA(IMAGE_ORDINAL(original_first_thunk->u1.Ordinal)));
                    } else {
                        IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)((char*)module_entry.hModule + original_first_thunk->u1.AddressOfData);

                        first_thunk->u1.Function = (ULONG_PTR)GetProcAddress(module, import_by_name->Name);
                    }
                }

                VirtualProtect(first_thunk, thunk_size, iat_protect, &iat_protect);
            }
        }
    } while (Module32Next(module_snapshot, &module_entry));

    CloseHandle(module_snapshot);

    return HOOK_RELOAD_SUCCEED;
}
