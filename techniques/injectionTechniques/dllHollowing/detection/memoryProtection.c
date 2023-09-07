#include <stdio.h> // Standard input/output definitions
#include <windows.h> // Windows libraries

// Function to check if a DLL is hollowed
int isDllHollowed(const char* dllName) { // dllName is the name of the DLL to check
    DWORD saveProtect = 0; // Variable to store the original memory protection of the entry point
    HMODULE hTargetDLL = LoadLibrary(dllName); // Load the DLL
    if (hTargetDLL == NULL) { // Check if the DLL is loaded
        printf("[!] LoadLibrary failed to load %s\n", dllName); // If LoadLibrary fails, print an error message
        return 0; // Return 0 to indicate that the DLL is not hollowed
    }
    PIMAGE_DOS_HEADER mzHeader = (PIMAGE_DOS_HEADER)hTargetDLL; // Get the DOS header of the DLL
    PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS)((char*)hTargetDLL + mzHeader->e_lfanew); // Get the PE header of the DLL
    void* entryPointDLL = (void*)((char*)hTargetDLL + peHeader->OptionalHeader.AddressOfEntryPoint); // Get the entry point of the DLL

    // Check if the memory protection of the entry point is modified
    if (VirtualProtect(entryPointDLL, sizeof(entryPointDLL), PAGE_READWRITE, &saveProtect)) { // If the memory protection is not modified, VirtualProtect will succeed
        VirtualProtect(entryPointDLL, sizeof(entryPointDLL), saveProtect, &saveProtect); // Restore the original memory protection
        printf("[!] Possible DLL Hollowing detected in %s\n", dllName); // Print an error message
        return 1; // Return 1 to indicate that the DLL is hollowed
    }

    return 0; // Return 0 to indicate that the DLL is not hollowed
}

int main() { // Main function
    const char* targetDll = "target.dll"; // Name of the DLL to check

    // Check if the target DLL is hollowed
    if (isDllHollowed(targetDll)) { // If the DLL is hollowed, print a message
        printf("DLL Hollowing detected!\n"); // Print a message
    } else { // If the DLL is not hollowed, print a message
        printf("No DLL Hollowing detected.\n"); // Print a message
    }

    return 0; // Return 0 to indicate that the program has completed successfully
} 