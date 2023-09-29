#include <windows.h>
#include <stdio.h>

// Function prototypes for the API functions
typedef HMODULE(WINAPI *pLoadLibrary)(LPCSTR);
typedef BOOL(WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef void* (__cdecl *pMemcpy)(void*, const void*, size_t);
typedef HANDLE(WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

// Original API function pointers
pLoadLibrary originalLoadLibrary;
pVirtualProtect originalVirtualProtect;
pMemcpy originalMemcpy;
pCreateThread originalCreateThread;

// Hooked API functions
HMODULE WINAPI MyLoadLibrary(LPCSTR lpFileName) {
    printf("LoadLibrary called with argument: %s\n", lpFileName);
    return originalLoadLibrary(lpFileName);
}

BOOL WINAPI MyVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    printf("VirtualProtect called\n");
    return originalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

void* __cdecl MyMemcpy(void* dest, const void* src, size_t count) {
    printf("memcpy called\n");
    return originalMemcpy(dest, src, count);
}

HANDLE WINAPI MyCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    printf("CreateThread called\n");
    return originalCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

// Function to set the hooks
void SetHooks() {
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    HMODULE hMSVCRT = GetModuleHandle("msvcrt.dll");

    originalLoadLibrary = (pLoadLibrary)GetProcAddress(hKernel32, "LoadLibraryA");
    originalVirtualProtect = (pVirtualProtect)GetProcAddress(hKernel32, "VirtualProtect");
    originalMemcpy = (pMemcpy)GetProcAddress(hMSVCRT, "memcpy");
    originalCreateThread = (pCreateThread)GetProcAddress(hKernel32, "CreateThread");

    // Replace the original API functions with our hooked functions
    WriteProcessMemory(GetCurrentProcess(), originalLoadLibrary, &MyLoadLibrary, sizeof(pLoadLibrary), NULL);
    WriteProcessMemory(GetCurrentProcess(), originalVirtualProtect, &MyVirtualProtect, sizeof(pVirtualProtect), NULL);
    WriteProcessMemory(GetCurrentProcess(), originalMemcpy, &MyMemcpy, sizeof(pMemcpy), NULL);
    WriteProcessMemory(GetCurrentProcess(), originalCreateThread, &MyCreateThread, sizeof(pCreateThread), NULL);
}

int main() {
    SetHooks();

    // Rest of your code...
    printf("Hooks set. Press Enter to exit.\n");
    getchar();

    return 0;
}