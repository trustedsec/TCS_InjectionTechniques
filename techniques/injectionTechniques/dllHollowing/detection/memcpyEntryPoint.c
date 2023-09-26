#include <windows.h>
#include <detours.h>
#include <stdio.h>

typedef void* (__cdecl *memcpy_t)(void* dest, const void* src, size_t count);
memcpy_t original_memcpy = memcpy;

void* __cdecl detour_memcpy(void* dest, const void* src, size_t count) {
    // Check if the destination is the entrypoint of amsi.dll
    // This is a simplified check, you may need to adjust it for your specific needs
    if (dest == GetProcAddress(GetModuleHandle("amsi.dll"), "DllEntryPoint")) {
        printf("memcpy is copying shellcode into the entrypoint of amsi.dll\n");
    }

    // Call the original memcpy function
    return original_memcpy(dest, src, count);
}

int main() {
    // Install the detour
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((void**)&original_memcpy, detour_memcpy);
    DetourTransactionCommit();

    // Your code here...
    printf("Monitoring memcpy calls. Press 'q' to quit.\n");
    char c;
    while ((c = getchar()) != 'q') {
        // Loop until 'q' is pressed
    }

    // Uninstall the detour before the program exits
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach((void**)&original_memcpy, detour_memcpy);
    DetourTransactionCommit();

    return 0;
}