include ../../Makefile.inc

SOURCES=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SOURCES))

all: $(OBJS)
	@mv $(OBJS) ../../$(BUILD_DIR)

clean:

