#!/usr/bin/env sh
x86_64-w64-mingw32-g++ dll_hollowing.c  -o ../bin/dll_hollow.exe -lntdll -static -D_WIN32_WINNT=0x602 
