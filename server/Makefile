CC=gcc
CFLAGS=-Wall -Wextra -pedantic
TARGET=modware-server
TARGET_FILES=modware-server.c

all: $(TARGET_FILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET_FILES)

docs:
	doxygen -g config.dox
	doxygen config.dox
	firefox html/index.html

clean: $(TARGET)
	rm $(TARGET)
