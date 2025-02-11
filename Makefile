CC := gcc
CFLAGS := -O2 -Wall -Wextra -pthread -lmnl -lnl-3 -lkeyutils
LDFLAGS := -lmnl -lnl-3

TARGET := kt
SOURCES := kt.c netlink.c
OBJECTS := $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)

.PHONY: all clean
