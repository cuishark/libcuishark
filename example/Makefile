
# CFLAGS += -I../ -g -O0
# CFLAGS += `pkg-config --cflags wireshark`
# CFLAGS += `pkg-config --cflags glib-2.0`
# LDFLAGS += -L../
# LDFLAGS += -lcuishark -lstdc++
# LDFLAGS += -lwiretap -lwsutil
# LDFLAGS += -lz -lm -lpcap
# LDFLAGS += `pkg-config --libs glib-2.0`
# LDFLAGS += `pkg-config --libs wireshark`

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
	-lglib-2.0  \
	-lgthread-2.0 \
	-lwireshark \
	-lwiretap -lwsutil -lz -lm -lpcap \
	-lcuishark

main:
	gcc $(CFLAGS) main.c $(LDFLAGS)

lib:
	make -C ../

run:
	sudo ./a.out -i lo

