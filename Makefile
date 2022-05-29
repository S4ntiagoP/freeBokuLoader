BOFNAME := freeBokuLoader
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip
OPTIONS := -masm=intel -Wall -I include

freeBokuLoader: clean
	$(CC_x64) -c source/entry.c -o dist/$(BOFNAME).x64.o $(OPTIONS) -DBOF
	$(STRIP_x64) --strip-unneeded dist/$(BOFNAME).x64.o

	$(CC_x86) -c source/entry.c -o dist/$(BOFNAME).x86.o $(OPTIONS) -DBOF
	$(STRIP_x86) --strip-unneeded dist/$(BOFNAME).x86.o

debug: clean
	$(CC_x64) -c source/entry.c -o dist/$(BOFNAME).x64.o $(OPTIONS) -DBOF -DDEBUG
	$(CC_x86) -c source/entry.c -o dist/$(BOFNAME).x86.o $(OPTIONS) -DBOF -DDEBUG

clean:
	rm -f dist/*
