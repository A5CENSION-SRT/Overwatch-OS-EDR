# Project Overwatch - Linux Userspace EDR
# Makefile
#
# Build targets:
#   make          - Build the overwatch executable
#   make debug    - Build with debug symbols
#   make clean    - Remove build artifacts
#   make test     - Build and run test programs
#   make install  - Install to /usr/local/bin (requires sudo)

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE
LDFLAGS = 
INCLUDES = -I./include

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = tests

# Source files
SOURCES = $(SRC_DIR)/main.c \
          $(SRC_DIR)/tracer.c \
          $(SRC_DIR)/decoder.c \
          $(SRC_DIR)/memory.c \
          $(SRC_DIR)/enforcer.c \
          $(SRC_DIR)/utils.c

# Object files
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Target executable
TARGET = $(BIN_DIR)/overwatch

# Default target
all: CFLAGS += -O2
all: $(TARGET)

# Debug build
debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET)

# Create directories if they don't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link object files to create executable
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo ""
	@echo "\033[1;34m╔════════════════════════════════════════════════════════════╗\033[0m"
	@echo "\033[1;34m║\033[1;38;5;208m       ⚡ BUILD SUCCESSFUL - Project Overwatch ⚡          \033[1;34m║\033[0m"
	@echo "\033[1;34m╠════════════════════════════════════════════════════════════╣\033[0m"
	@echo "\033[1;34m║\033[0m  Binary: \033[1;32m$(TARGET)\033[0m                                 \033[1;34m║\033[0m"
	@echo "\033[1;34m║\033[0m  Usage:  $(TARGET) -- <program> [args]             \033[1;34m║\033[0m"
	@echo "\033[1;34m╚════════════════════════════════════════════════════════════╝\033[0m"
	@echo ""

# Build test malware samples
test-samples: | $(BIN_DIR)
	$(CC) $(TEST_DIR)/test_file_access.c -o $(BIN_DIR)/test_file_access
	$(CC) $(TEST_DIR)/test_network.c -o $(BIN_DIR)/test_network
	$(CC) $(TEST_DIR)/test_malicious.c -o $(BIN_DIR)/test_malicious
	@echo "Test samples built in $(BIN_DIR)/"

# Run basic tests
test: $(TARGET) test-samples
	@echo "Running basic functionality test..."
	@echo "Testing with 'ls -la':"
	./$(TARGET) -- ls -la
	@echo ""
	@echo "Testing with 'cat /etc/hostname':"
	./$(TARGET) -- cat /etc/hostname

# Install to system
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/overwatch
	@echo "Installed to /usr/local/bin/overwatch"

# Uninstall from system
uninstall:
	sudo rm -f /usr/local/bin/overwatch
	@echo "Uninstalled from /usr/local/bin/"

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleaned build artifacts"

# Show help
help:
	@echo "Project Overwatch - Linux Userspace EDR"
	@echo ""
	@echo "Build targets:"
	@echo "  make          - Build the overwatch executable (optimized)"
	@echo "  make debug    - Build with debug symbols"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make test     - Build and run basic tests"
	@echo "  make test-samples - Build test programs only"
	@echo "  make install  - Install to /usr/local/bin (requires sudo)"
	@echo "  make uninstall - Remove from /usr/local/bin"
	@echo ""
	@echo "Quick start:"
	@echo "  make && ./bin/overwatch -- ls -la"

# Phony targets
.PHONY: all debug clean test test-samples install uninstall help
