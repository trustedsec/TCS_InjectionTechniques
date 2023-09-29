#!/usr/bin/env sh
x86_64-w64-mingw32-gcc dll_sethook.c -w -fpermissive -static  -o ../bin/dll_sethook.exe
x86_64-w64-mingw32-gcc evil.c -w -fpermissive -static  -shared -o ../bin/evil.dll
