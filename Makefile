.SUFIXES: .c .o

include Makefile.inc

TARGET := openbras

all: $(TARGET)

$(TARGET):
	@rm -f $(BUILD_DIR)/*.o ; mkdir -p ${BUILD_DIR} ; cd $(SRC_DIR) ; make ; cd ..
	$(C) -o $(TARGET) $(BUILD_DIR)/*.o -pthread -lrt -lm

clean:
	rm -f $(BUILD_DIR)/*.o
	rm $(TARGET)
	@cd $(SRC_DIR) ; make clean ; cd ..
