CC=gcc
CFLAGS=-Wall -Wextra -pedantic
TARGET=modware-server
TARGET_FILES=modware-server.c

all: $(TARGET_FILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET_FILES)

clean: $(TARGET)
	rm $(TARGET)
