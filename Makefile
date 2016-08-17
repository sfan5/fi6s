CFLAGS = -pipe -std=c11 -Wall -Wextra -O0 -g
LDFLAGS = -g
LIBS =

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin

SRC = main.c
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
