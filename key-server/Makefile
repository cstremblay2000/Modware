CC=gcc
CFLAGS=-Wall -Wextra -pedantic
TARGET=key-server
TARGET_FILES=key-server.c

all: $(TARGET_FILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET_FILES)

clean: $(TARGET)
	rm $(TARGET)
