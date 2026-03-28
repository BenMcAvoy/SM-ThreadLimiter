#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <imagehlp.h>

#pragma comment(lib, "shell32.lib")

#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <cstring>

static unsigned int g_thread_count = 4;

static unsigned int __cdecl Hook_GetProcessorCount() {
    return g_thread_count;
}

static unsigned int ParseThreadCount(unsigned int fallback) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return fallback;

    unsigned int result = fallback;
    for (int i = 1; i < argc - 1; ++i) {
        if (_wcsicmp(argv[i], L"-threads") == 0) {
            int val = _wtoi(argv[i + 1]);
            if (val >= 1)
                result = (unsigned int)val;
            break;
        }
    }

    LocalFree(argv);
    return result;
}

// finds an IAT slot by module+export name and swaps the pointer
static bool PatchIATByName(HMODULE hExe, const char* module, const char* fn, void* replacement) {
    auto* base = reinterpret_cast<const BYTE*>(hExe);
    auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto* nt   = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

    const IMAGE_DATA_DIRECTORY& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!import_dir.VirtualAddress || !import_dir.Size)
        return false;

    auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + import_dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        if (_stricmp(reinterpret_cast<const char*>(base + desc->Name), module) != 0)
            continue;

        auto* orig = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
        auto* iat  = reinterpret_cast<IMAGE_THUNK_DATA*>(const_cast<BYTE*>(base) + desc->FirstThunk);

        for (; orig->u1.AddressOfData; ++orig, ++iat) {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal))
                continue;

            auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + orig->u1.AddressOfData);
            if (strcmp(ibn->Name, fn) != 0)
                continue;

            DWORD old = 0;
            VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
            iat->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
            return true;
        }
    }

    return false;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    g_thread_count = ParseThreadCount(4);

    HMODULE hExe = GetModuleHandleW(nullptr);
    if (!hExe)
        return FALSE;

    PatchIATByName(hExe, "CONCRT140.dll", "?GetProcessorCount@Concurrency@@YAIXZ",
        reinterpret_cast<void*>(&Hook_GetProcessorCount));

    return TRUE;
}
