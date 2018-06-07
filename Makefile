
CFLAGS += -I. -g -O0
CFLAGS += `pkg-config --cflags wireshark`
CFLAGS += `pkg-config --cflags glib-2.0`
LDFLAGS += `pkg-config --libs wireshark`
LDFLAGS += `pkg-config --libs glib-2.0`
LDFLAGS += -lwiretap -lwsutil -lz -lm -lpcap
CXXFLAGS += $(CFLAGS) -std=c++11

CSRC = \
	ui/capture_ui_utils.c ui/failure_message.c \
	ui/dissect_opts.c ui/decode_as_utils.c \
	ui/filter_files.c ui/iface_toolbar.c ui/util.c \
	capchild/capture_ifinfo.c capchild/capture_sync.c \
	caputils/capture-pcap-util-unix.c \
	caputils/capture-pcap-util.c version_info.c cfile.c \
	capture_opts.c capture_file.c file_packet_provider.c \
	frame_tvbuff.c sync_pipe_write.c extcap.c \
	extcap_parser.c extcap_spawn.c print_columns.c

CXXSRC = cuishark.cc
COBJ = $(CSRC:.c=.o)
CXXOBJ = $(CXXSRC:.cc=.o)
OBJ = $(COBJ) $(CXXOBJ)
TARGET = libcuishark.a

test: lib
	gcc $(CFLAGS) main.c -L. -lcuishark $(LDFLAGS) -lstdc++

lib: $(OBJ)
	ar rcs $(TARGET) $(OBJ)

clean:
	rm -f $(OBJ) a.out *.a

install: lib
	cp $(TARGET) /usr/local/lib

uninstall:
	rm -f /usr/local/lib/libcuishark.a

run:
	sudo ./a.out -i lo -Y "icmp"


