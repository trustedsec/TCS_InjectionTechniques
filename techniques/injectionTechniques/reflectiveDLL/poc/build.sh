#!/usr/bin/env sh
x86_64-w64-mingw32-gcc reflective_dll.c -w -masm=intel -fpermissive -static -lntdll -lpsapi -lws2_32 -Wl,--subsystem,console -o ../bin/reflect_dll.exe
