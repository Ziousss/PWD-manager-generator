CC := gcc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Wpedantic -g
TARGET := pwd-manager
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

PKG_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null || echo)
PKG_LIBS := $(shell pkg-config --libs libsodium 2>/dev/null || echo -lsodium)
PKG_LIBS := $(PKG_LIBS) -lm

ifeq (,$(PKG_CFLAGS))
    PKG_CFLAGS :=
endif

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(PKG_LIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	-rm -f $(OBJS) $(TARGET)
