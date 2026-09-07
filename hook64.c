#include "hook.h"

#include <windows.h>

char jumper[] = {
    0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x50,
    0xC3,
    0xCC, 0xCC, 0xCC, 0xCC
};

hook_status hook_module(unsigned short* module_name, hook_detour_entry detours[], int detour_count) {
    if (!module_name) {
        return HOOK_INVALID_MOD_NAME;
    }

    void* module = GetModuleHandle(module_name);

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
