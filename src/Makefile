include ../Makefile.inc

OBJS = openbras.o

all: $(OBJS) dirs
	@mv $(OBJS) ../$(BUILD_DIR)/

dirs:
	@cd $(FUNCTIONS_DIR) ; make ; cd ..

clean:
	@cd $(FUNCTIONS_DIR) ; make clean ; cd ..

