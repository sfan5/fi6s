BUILD_TYPE ?= debug

CFLAGS = -pipe -std=gnu11 -pthread -fno-strict-aliasing
CFLAGS += -Wall -Wextra -Wno-sign-compare -Wcast-align
LDFLAGS =
LIBS = -lpcap

ifeq ($(BUILD_TYPE),debug)
CFLAGS += -O1 -g
else
ifeq ($(BUILD_TYPE),release)
CFLAGS += -O3 -ggdb -DNDEBUG
else
$(error BUILD_TYPE must be one of release or debug)
endif
endif

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin

SRC = \
	main.c util.c \
	scan.c scan-responder.c scan-reader.c \
	target-parse.c target-gen.c \
	rawsock-pcap.c rawsock-frame.c rawsock-routes.c \
	output-list.c output-json.c output-binary.c \
	tcp.c tcp-state.c udp.c icmp.c \
	banner.c \
	binary-write.c binary-read.c
OBJ = $(addprefix obj/, $(addsuffix .o, $(basename $(SRC)))) 

all: fi6s

fi6s: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LIBS)

obj/%.o: src/%.c src/*.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

install:
	install -pDm755 fi6s $(DESTDIR)$(BINDIR)/fi6s

.PHONY: clean
