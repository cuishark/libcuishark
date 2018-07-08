
# CFLAGS += -I. -g -O0
# CFLAGS += `pkg-config --cflags wireshark`
# CFLAGS += `pkg-config --cflags glib-2.0`
# CXXFLAGS += $(CFLAGS) -std=c++11
# LDFLAGS += `pkg-config --libs wireshark`
# LDFLAGS += `pkg-config --libs glib-2.0`
# LDFLAGS += -lwiretap -lwsutil -lz -lm -lpcap

CFLAGS += \
	-I. -g -O0 -pthread \
	-I/usr/include \
	-I/usr/include/wireshark \
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

C_SRC = $(shell find . -name "*.c")
C_OBJ = $(C_SRC:.c=.o)
CXX_SRC = $(shell find . -name "*.cc")
CXX_OBJ = $(CXX_SRC:.cc=.o)
TARGET = libcuishark.a

lib: $(C_OBJ) $(CXX_OBJ)
	ar rcs $(TARGET) $(C_OBJ) $(CXX_OBJ)

clean:
	rm -f *.a $(C_OBJ) $(CXX_OBJ) $(TARGET)

install: lib
	cp $(TARGET) /usr/local/lib
	cp cuishark.h /usr/local/include

uninstall:
	rm -f /usr/local/lib/libcuishark.a
	rm -f /usr/local/include/cuishark.h

