#include <windows.h>
#include <stdbool.h>

// TODO get the orig value of the messageboxa stored in there
HANDLE ptrHook = NULL;

int myFunction( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType )
{
    printf("caption (%s) body (%s)\n", lpCaption, lpText );
    void (*msgbox)(HWND, LPCSTR, LPCSTR,UINT) = (DWORD_PTR)ptrHook;
    (*msgbox)(hWnd, lpText, lpCaption, uType);

}

void patch()
{
    printf("In evil doing evil things\n");
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hModule = GetModuleHandle(0);
    printf("hModule (%08llX)\n", hModule);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule+ dosHeaders->e_lfanew);
    HANDLE tmpHookAddr = NULL;

    // Check if the dll is x86 or x64
    if( ntHeaders->FileHeader.Machine ==  IMAGE_FILE_MACHINE_I386)
    {
        // Only supporst 64 bit dll's
        printf("Invalid DLL version only supports x64\n");
        return -1;
    } 
    SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

    // resolve import address table
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)hModule);
    LPCSTR libraryName = "";
    HMODULE library = NULL;
    HANDLE hookOffset = -1;
    while (importDescriptor->Name != NULL)
    {
//        printf("ImportDescriptor (%llX)\n", importDescriptor);
        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)hModule;
        printf("LibraryName = %s\n", libraryName);
        if( strcmp(libraryName, "USER32.dll") == 0)
        {
            hookOffset = importDescriptor->FirstThunk;
            break;
        }
        importDescriptor++;
    }
    if( hookOffset == -1) 
    {
        printf("Hook not found\n");
        return;
    }
    tmpHookAddr = (DWORD_PTR)hModule + (DWORD_PTR)hookOffset;
    printf("Found MessageBoxA (%llX) or (%llX)\n", hookOffset, tmpHookAddr);
    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)tmpHookAddr;
    ptrHook = thunk->u1.Function;
    thunk->u1.Function = &myFunction;
}

bool __stdcall DllMain( HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    switch( dwReason )
    {
        case DLL_PROCESS_ATTACH:
            patch();
            break;
    }
    return TRUE;
}
