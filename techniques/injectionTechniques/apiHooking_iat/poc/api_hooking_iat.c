#include <windows.h>
#include<stdio.h>

int main( int argc, char* argv[] )
{
    printf("Hello me \n");

    int msgboxID = MessageBox( NULL, "This is a test", "Are you sure?", MB_OKCANCEL);
    
    LoadLibrary("evil.dll");
    msgboxID = MessageBox( NULL, "This is a second test", "Are you sure?", MB_OKCANCEL);
}


