BUILD_TYPE ?= debug

CFLAGS = -pipe -std=gnu11 -pthread
CFLAGS += -Wall -Wextra -Wno-sign-compare -Wcast-align -Werror=vla
LDFLAGS =
LIBS = -lpcap

ifeq ($(BUILD_TYPE),debug)
CFLAGS += -O1 -ggdb
#CFLAGS += -fsanitize=type
#CFLAGS += -Wstack-usage=6144
else
ifeq ($(BUILD_TYPE),release)
CFLAGS += -O3 -g -DNDEBUG
ifeq ($(FUZZ),)
CFLAGS += -flto
LDFLAGS += -flto
endif
else
$(error BUILD_TYPE must be one of release or debug)
endif
endif
ifeq ($(ASAN),1)
CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
endif
ifeq ($(UBSAN),1)
CFLAGS += -fsanitize=undefined
LDFLAGS += -fsanitize=undefined
endif

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin

SRC = \
	util.c \
	scan.c scan-responder.c scan-reader.c \
	target-parse.c target-gen.c \
	rawsock-pcap.c rawsock-frame.c rawsock-routes.c \
	output.c output-list.c output-json.c output-binary.c \
	tcp.c tcp-state.c udp.c icmp.c \
	banner.c \
	binary-write.c binary-read.c

ifeq ($(FUZZ)$(BENCH),)
SRC += main.c
else
ifeq ($(BENCH),)
SRC += fuzz-$(FUZZ).c
else
SRC += bench-$(BENCH).c
endif
endif

OBJ = $(addprefix obj/, $(addsuffix .o, $(basename $(SRC))))

all: fi6s

fi6s: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

obj/%.o: src/%.c src/*.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

install:
	install -pDm755 fi6s $(DESTDIR)$(BINDIR)/fi6s

.PHONY: clean
