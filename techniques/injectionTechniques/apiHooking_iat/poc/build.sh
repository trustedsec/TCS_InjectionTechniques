#!/usr/bin/env sh
x86_64-w64-mingw32-gcc api_hooking_iat.c -w -fpermissive -static  -o ../bin/api_hooking_ait.exe
x86_64-w64-mingw32-gcc evil.c -w -fpermissive -static  -shared -o ../bin/evil.dll
