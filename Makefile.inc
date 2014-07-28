
SRC_DIR := src
FUNCTIONS_DIR := functions
BUILD_DIR := build

C := gcc
INCLUDE := -I. -I../include -I../../include -I./$(SRC_DIR)/$(FUNCTIONS_DIR) -I../$(SRC_DIR)/$(FUNCTIONS_DIR)
CFLAGS := -g $(INCLUDE)

.c.o:
	$(C) $(CFLAGS) -c -o $*.o $*.c
