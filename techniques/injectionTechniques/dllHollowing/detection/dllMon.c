// dllMonitor.c
#include <windows.h>
#include <stdio.h>

// Function to check for DLL Hollowing or Module Stomping
void checkForHollowingOrStomping(DWORD pid, char* targetDll) {
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("OpenProcess failed. Error: %d\n", GetLastError());
        return;
    }

    // Get the base address of the target DLL
    HMODULE hDll = GetModuleHandle(targetDll);
    if (hDll == NULL) {
        printf("GetModuleHandle failed. Error: %d\n", GetLastError());
        return;
    }

    // Get the size of the target DLL
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hDll;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hDll + dosHeader->e_lfanew);
    DWORD sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    // Allocate memory for the DLL image
    BYTE* dllImage = (BYTE*)malloc(sizeOfImage);
    if (dllImage == NULL) {
        printf("Memory allocation failed.\n");
        return;
    }

    // Read the DLL image from the target process
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, hDll, dllImage, sizeOfImage, &bytesRead)) {
        printf("ReadProcessMemory failed. Error: %d\n", GetLastError());
        free(dllImage);
        return;
    }

    // Compare the DLL image with the actual DLL file
    FILE* file = fopen(targetDll, "rb");
    if (file == NULL) {
        printf("Failed to open DLL file.\n");
        free(dllImage);
        return;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    BYTE* fileBuffer = (BYTE*)malloc(fileSize);
    if (fileBuffer == NULL) {
        printf("Memory allocation failed.\n");
        free(dllImage);
        fclose(file);
        return;
    }

    fread(fileBuffer, 1, fileSize, file);

    if (memcmp(dllImage, fileBuffer, fileSize) != 0) {
        printf("Possible DLL Hollowing or Module Stomping detected.\n");
    }

    // Clean up
    free(dllImage);
    free(fileBuffer);
    fclose(file);
    CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <PID> <DLL Path>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    char* targetDll = argv[2];

    checkForHollowingOrStomping(pid, targetDll);

    return 0;
}