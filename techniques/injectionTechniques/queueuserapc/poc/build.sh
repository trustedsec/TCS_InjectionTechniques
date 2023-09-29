#!/usr/bin/env sh
x86_64-w64-mingw32-gcc queueuserapc.c -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,console -o ../bin/queueuserapc.exe
