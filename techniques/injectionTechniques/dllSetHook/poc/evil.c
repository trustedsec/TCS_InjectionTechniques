#include <windows.h>
#include <stdbool.h>
__declspec(dllexport) LRESULT CALLBACK  evil_func( int nCode, WPARAM wParam, LPARAM lParam )
{
    int msgboxID = MessageBox( NULL, "This is a test", "Are you sure?", MB_OKCANCEL);
    return CallNextHookEx( NULL, nCode, wParam, lParam );
}

bool __stdcall DllMain( HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    switch( dwReason )
    {
        case DLL_PROCESS_ATTACH:
            break;
    }
    return TRUE;
}
