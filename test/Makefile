
# CFLAGS += `pkg-config --cflags wireshark`
# CFLAGS += `pkg-config --cflags glib-2.0`
# CFLAGS += -g -O0
# LDFLAGS += `pkg-config --libs wireshark`
# LDFLAGS += `pkg-config --libs glib-2.0`
# LDFLAGS += -lwiretap -lwsutil -lz -lm -lpcap

CFLAGS += \
	-I. -g -O0 -pthread \
	-I/usr/include \
	-I/usr/local/include \
	-I/usr/local/include/wireshark \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
	-I/usr/include/glib-2.0
CXXFLAGS += $(CFLAGS) -std=c++11
LDFLAGS +=  \
	-L/usr/local/lib \
	-pthread \
	-lgthread-2.0 \
	-lglib-2.0  \
	-lwireshark -Wl,--export-dynamic \
	-lwiretap -lwsutil -lz -lm -lpcap

test:
	gcc $(CFLAGS) main.c -L../lib -I../lib -lcuishark $(LDFLAGS) -lstdc++

all: test
	./a.out -r short.pcap
	./a.out -r vlan.pcap

clean:
	rm -f $(OBJ) a.out *.a

