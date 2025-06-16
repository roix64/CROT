CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE -O2
DEBUG_FLAGS = -g -DDEBUG
LIBS = -lpthread

TARGET = webserver
DEBUG_TARGET = webserver_debug
SOURCES = webframework.c complete_example.c

all: $(TARGET)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(DEBUG_TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

$(DEBUG_TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -o $(DEBUG_TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET) $(DEBUG_TARGET)

install_deps:
	sudo apt-get update
	sudo apt-get install build-essential curl

test: $(TARGET)
	./$(TARGET) &
	sleep 2
	curl -s http://localhost:8080/
	curl -s http://localhost:8080/users/123
	curl -s -H "Authorization: Bearer token123" http://localhost:8080/api/status
	pkill -f webserver

static_dir:
	mkdir -p static
	echo "<h1>Static File</h1><p>This is served from static directory</p>" > static/index.html

run: $(TARGET) static_dir
	./$(TARGET)

.PHONY: all debug clean install_deps test static_dir run