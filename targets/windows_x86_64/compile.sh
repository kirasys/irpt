if [[ "$OSTYPE" == "linux-gnu" ]]; then
	mkdir bin/ 2> /dev/null
	mkdir bin/loader/ 2> /dev/null
	mkdir bin/agent/ 2> /dev/null

	if x86_64-w64-mingw32-gcc -v 2> /dev/null && x86_64-w64-mingw32-g++ -v 2> /dev/null; then
		printf "\tCompiling loader...\n"
		x86_64-w64-mingw32-g++ src/loader/loader.c -I ../ -o bin/loader/loader.exe -Wall -lpsapi
		printf "\tCompiling agent...\n"
        x86_64-w64-mingw32-g++ src/agent/agent.cpp -I ../ -o bin/agent/agent.exe -mwindows -lpsapi -lntdll -Wall 
		printf "\tCompiling repro...\n"
        x86_64-w64-mingw32-g++ src/agent/repro.cpp -I ../ -o bin/agent/repro.exe -mwindows -lpsapi -lntdll -Wall 
	else
		printf "\tCould not find x86_64-w64-mingw32-gcc/g++! Skipping..\n\t(Try sudo apt install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 to fix this)"
	fi 
else
	printf "\tError: Need to run Linux to compile these components! Skipping..!\n"
fi


# sudo apt install gcc-mingw-w64-x86-64
# sudo apt install gcc-mingw-w64-x86-64
# linux_x86-64-2$ x86_64-w64-mingw32-gcc -v
