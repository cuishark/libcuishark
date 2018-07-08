
CFLAGS += `pkg-config --cflags wireshark`
CFLAGS += `pkg-config --cflags glib-2.0`
LDFLAGS += `pkg-config --libs wireshark`
LDFLAGS += `pkg-config --libs glib-2.0`
LDFLAGS += -lwiretap -lwsutil -lz -lm -lpcap

test: compile
	./a.out

compile:
	g++ $(CFLAGS) -std=c++11 -L.. -I..  main.cc \
		-lcuishark $(LDFLAGS) -lgtest -lgtest_main -lpthread

clean:
	rm -f $(OBJ) a.out *.a

