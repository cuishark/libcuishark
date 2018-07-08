
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

test: compile
	./a.out

compile:
	g++ $(CFLAGS) -std=c++11 -L.. -I..  main.cc \
		-lcuishark $(LDFLAGS) -lgtest -lgtest_main -lpthread

clean:
	rm -f $(OBJ) a.out *.a

