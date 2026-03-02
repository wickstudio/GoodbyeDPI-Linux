TARGET = goodbyedpi
CC = gcc

CFLAGS = -std=c99 -pipe -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
         -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security \
         -Wshadow -Wnull-dereference -Warray-bounds=2 \
         -D_GNU_SOURCE

LDFLAGS = -fstack-protector-strong
LIBS = -lnetfilter_queue -lnfnetlink -lm

ifdef DEBUG
	CFLAGS += -DDEBUG -g -O0
endif

.PHONY: default all clean install uninstall

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c utils/repl_str.c))
HEADERS = $(wildcard *.h utils/*.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LIBS) -o $@
	@echo ""
	@echo "Build complete: ./$(TARGET)"
	@echo "Run with: sudo ./$(TARGET)"

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/bin/$(TARGET)
	@echo "Installed to /usr/local/bin/$(TARGET)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)

clean:
	-rm -f *.o utils/*.o
	-rm -f $(TARGET)
