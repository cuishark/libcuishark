
CFLAGS += -I../ -g -O0
CFLAGS += `pkg-config --cflags wireshark`
CFLAGS += `pkg-config --cflags glib-2.0`
LDFLAGS += -L../
LDFLAGS += -lcuishark -lstdc++
LDFLAGS += -lwiretap -lwsutil
LDFLAGS += -lz -lm -lpcap
LDFLAGS += `pkg-config --libs glib-2.0`
LDFLAGS += `pkg-config --libs wireshark`

main:
	gcc $(CFLAGS) main.c $(LDFLAGS)

lib:
	make -C ../

run:
	sudo ./a.out -i lo

