#!/bin/bash
x86_64-w64-mingw32-g++ ./src/loader.c -I ./include -o ./bin/loader.exe -mwindows -lpsapi -lntdll -Wall
