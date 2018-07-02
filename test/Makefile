
CFLAGS += `pkg-config --cflags wireshark`
CFLAGS += `pkg-config --cflags glib-2.0`
CFLAGS += -g -O0
LDFLAGS += `pkg-config --libs wireshark`
LDFLAGS += `pkg-config --libs glib-2.0`
LDFLAGS += -lwiretap -lwsutil -lz -lm -lpcap

test:
	gcc $(CFLAGS) main.c -L../lib -I../lib -lcuishark $(LDFLAGS) -lstdc++

all: test
	./a.out -r short.pcap
	./a.out -r vlan.pcap

clean:
	rm -f $(OBJ) a.out *.a

