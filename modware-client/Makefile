CC=gcc
CFLAGS=-Wall -Wextra -pedantic
TARGET=modware-client
TARGET_FILES=modware-client.c

all: $(TARGET_FILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET_FILES)

clean: $(TARGET)
	rm $(TARGET)
