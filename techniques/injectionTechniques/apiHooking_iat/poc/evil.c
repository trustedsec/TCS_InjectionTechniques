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
void* getIATAddress( char* libName, char* funcName )
{
    HMODULE hModule = GetModuleHandle(0);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule+ dosHeaders->e_lfanew);
    HANDLE tmpHookAddr = NULL;

    // resolve import address table
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)hModule);
    HANDLE library = NULL;
    while (importDescriptor->Name != NULL)
    {
        LPCSTR libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)hModule;
        if( strcmp(libraryName, libName) == 0)
        {
            library = importDescriptor->FirstThunk;
            break;
        }
        importDescriptor++;
    }
    if( library == NULL) 
    {
        printf("Hook not found\n");
        return;
    }
	HANDLE ptrFuncNameOffset = importDescriptor->Characteristics + (DWORD_PTR)hModule;
	int funcNameOffset = (int)(*(int*)ptrFuncNameOffset);
	int count = 0;
	while( funcNameOffset != 0)
	{
		char* lFuncName = (char*)(*(int*)(ptrFuncNameOffset + count*8) + (DWORD_PTR)hModule+2);
		if( strcmp( lFuncName, funcName) == 0) break;
		count += 1;	
		funcNameOffset = (int)(*(int*)ptrFuncNameOffset + count*8);
	}
    tmpHookAddr = (DWORD_PTR)hModule + (DWORD_PTR)library + count*8;
	void *ret = (void*)tmpHookAddr;
    printf("Found %s (%llX)\n", funcName, ret );
	return ret;
}

void patch()
{
    printf("In evil doing evil things\n");
    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA )getIATAddress("USER32.dll","MessageBoxA");
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
