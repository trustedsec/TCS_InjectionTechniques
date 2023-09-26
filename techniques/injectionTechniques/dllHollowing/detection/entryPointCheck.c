#include <windows.h>
#include <stdio.h>

int main() {
    char dllName[] = "amsi.dll";  // Replace this with the name of the DLL you want to monitor
    HMODULE hTargetDLL = GetModuleHandle(dllName);

    if (hTargetDLL == NULL) {
        printf("Failed to load %s\n", dllName);
        return 1;
    }

    PIMAGE_DOS_HEADER mzHeader = (PIMAGE_DOS_HEADER) hTargetDLL;
    PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS) ((char*)hTargetDLL + mzHeader->e_lfanew);
    DWORD originalEntryPoint = peHeader->OptionalHeader.AddressOfEntryPoint;
    void *entryPointDLL = (void*)((char*)hTargetDLL + originalEntryPoint);

    DWORD originalCodeSize = peHeader->OptionalHeader.SizeOfCode;
    printf("Successfully monitoring %s with original code size: %lu\n", dllName, originalCodeSize);

    unsigned char *originalCode = (unsigned char*) malloc(originalCodeSize);
    memcpy(originalCode, entryPointDLL, originalCodeSize);

    while (1) {
        Sleep(1000);  // Check every second

        // Reload the DLL and check its current entry point and code size
        HMODULE hCurrentDLL = GetModuleHandle(dllName);
        PIMAGE_DOS_HEADER currentMzHeader = (PIMAGE_DOS_HEADER) hCurrentDLL;
        PIMAGE_NT_HEADERS currentPeHeader = (PIMAGE_NT_HEADERS) ((char*)hCurrentDLL + currentMzHeader->e_lfanew);
        DWORD currentEntryPoint = currentPeHeader->OptionalHeader.AddressOfEntryPoint;
        void *newEntryPointDLL = (void*)((char*)hCurrentDLL + currentEntryPoint);
        DWORD currentCodeSize = currentPeHeader->OptionalHeader.SizeOfCode;

        if (originalEntryPoint != currentEntryPoint) {
            printf("The entry point of %s has changed!\n", dllName);
            printf("Old entry point address: %p, first 10 bytes:\n", entryPointDLL);
            for (int i = 0; i < 10; i++) {
                printf("%02x ", ((unsigned char*)entryPointDLL)[i]);
            }
            printf("\n");

            printf("New entry point address: %p, first 10 bytes:\n", newEntryPointDLL);
            for (int i = 0; i < 10; i++) {
                printf("%02x ", ((unsigned char*)newEntryPointDLL)[i]);
            }
            printf("\n");

            break;
        }

        unsigned char *currentCode = (unsigned char*) malloc(currentCodeSize);
        memcpy(currentCode, newEntryPointDLL, currentCodeSize);

        if (memcmp(originalCode, currentCode, originalCodeSize) != 0) {
            printf("The code at the entry point of %s has changed!\n", dllName);
            printf("Old entry point address: %p, first 10 bytes:\n", entryPointDLL);
            for (int i = 0; i < 10; i++) {
                printf("%02x ", ((unsigned char*)entryPointDLL)[i]);
            }
            printf("\n");

            printf("New entry point address: %p, first 10 bytes:\n", newEntryPointDLL);
            for (int i = 0; i < 10; i++) {
                printf("%02x ", ((unsigned char*)newEntryPointDLL)[i]);
            }
            printf("\n");

            break;
        }

        free(currentCode);
    }

    free(originalCode);
    return 0;
}