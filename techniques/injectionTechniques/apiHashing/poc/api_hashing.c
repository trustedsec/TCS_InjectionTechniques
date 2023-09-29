#include <windows.h>
#include<stdio.h>

#define ROR(x,y) ((unsigned)(x) >> (y) | (unsigned)(x) << 32 - (y))
unsigned ror(unsigned x, unsigned y)
{
    return ROR(x, y);
}

UINT getHash( char* name )
{
	UINT l_hash = 0;
	char ch = name[0]; 
	int index = 0;

	while( ch != '\x00')
	{
		l_hash = ror(l_hash, 0xd);
		l_hash += name[index];
		index++;
		ch = name[index];
	}
//	printf("hashed (%s) (%08X)\n", name, l_hash);
	return l_hash;
}

//void* callFunction( UINT hash )
void* callFunction( UINT libNameHash, UINT funcNameHash )
{
    HMODULE hModule = GetModuleHandle(0);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule+ dosHeaders->e_lfanew);
    HANDLE tmpHookAddr = NULL;

	printf("Module Address (%llX)\n", hModule);
    // resolve import address table
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)hModule);
    HANDLE library = NULL;
    while (importDescriptor->Name != NULL)
    {
        LPCSTR libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)hModule;
        if( getHash(libraryName) ==  libNameHash)
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
    printf("import descriptor at (%llX) \n", importDescriptor);
	HANDLE ptrFuncNameOffset = importDescriptor->Characteristics + (DWORD_PTR)hModule;
	int funcNameOffset = (int)(*(int*)ptrFuncNameOffset);
	int count = 0;
	while( funcNameOffset != 0)
	{
		char* lFuncName = (char*)(*(int*)(ptrFuncNameOffset + count*8) + (DWORD_PTR)hModule+2);
		printf("Test function name (%s)\n",  lFuncName);
		if( getHash(lFuncName) == funcNameHash) break;
		count += 1;	
		funcNameOffset = (int)(*(int*)ptrFuncNameOffset + count*8);
	}
    tmpHookAddr = (DWORD_PTR)hModule + (DWORD_PTR)library + count*8;
	void *ret = (void*)tmpHookAddr;
    printf("Found %08X (%llX)\n", funcNameHash, *(DWORD_PTR*)ret );
	return *(DWORD_PTR*)ret;
}
int main( int argc, char* argv[] )
{
    printf("Hello me \n");

    int msgboxID = MessageBox( NULL, "This is a test", "Are you sure?", MB_OKCANCEL);
    
//	int (*fun_ptr_1)( LPCSTR ) = callFunction( getHash("KERNEL32.dll"), getHash("GetModuleHandleA") );
//	int (*fun_ptr_2)( HWND, LPCSTR, LPCSTR, UINT ) = callFunction( getHash("USER32.dll"), getHash("MessageBoxA") );
	int (*fun_ptr_1)( LPCSTR ) = callFunction( 0x6f2bd237, 0xd3324904 ); // GetModuleHandleA
	int (*fun_ptr_2)( HWND, LPCSTR, LPCSTR, UINT ) = callFunction( 0x33adea26, 0xbc4da2a8 ); // MessageBoxA

	printf("Got function pointers\n");

	HMODULE ret = (*fun_ptr_1)( NULL);
	printf("GetModuleHandleA function pointer (%llX)\n", ret);
	(*fun_ptr_2)( NULL, "This is a second test", "Are you sure?", MB_OKCANCEL );
}
