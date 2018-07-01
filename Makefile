
all: test example
.PHONY: lib test install uninstall run

test: lib
	make -C test all

lib:
	make -C lib

install: lib
	make -C lib install

uninstall:
	make -C lib uninstall

run:
	sudo ./a.out -i lo


