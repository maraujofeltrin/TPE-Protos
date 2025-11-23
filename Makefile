# Compilador y flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pedantic -g -O0 -D_POSIX_C_SOURCE=200809L
LDFLAGS = 
TEST_LIBS = -lcheck -lm -lrt -lpthread -lsubunit

# Directorios
SRC_DIR = src
UTILS_DIR = $(SRC_DIR)/utils
SERVER_DIR = $(SRC_DIR)/server
CLIENT_DIR = $(SRC_DIR)/client
UTILS_INCLUDE_DIR = $(UTILS_DIR)/include
SERVER_INCLUDE_DIR = $(SERVER_DIR)/include
CLIENT_INCLUDE_DIR = $(CLIENT_DIR)/include
TEST_DIR = tests
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
BIN_DIR = $(BUILD_DIR)/bin

# Archivos fuente
UTILS_SOURCES = $(wildcard $(UTILS_DIR)/*.c)
SERVER_SOURCES = $(wildcard $(SERVER_DIR)/*.c)
CLIENT_SOURCES = $(wildcard $(CLIENT_DIR)/*.c)
TEST_SOURCES = $(wildcard $(TEST_DIR)/*.c)

# Archivos objeto
UTILS_OBJECTS = $(UTILS_SOURCES:$(UTILS_DIR)/%.c=$(OBJ_DIR)/utils/%.o)
SERVER_OBJECTS = $(SERVER_SOURCES:$(SERVER_DIR)/%.c=$(OBJ_DIR)/server/%.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:$(CLIENT_DIR)/%.c=$(OBJ_DIR)/client/%.o)

# Ejecutables de tests
TEST_NAMES = $(TEST_SOURCES:$(TEST_DIR)/%.c=%)
TEST_EXECUTABLES = $(TEST_NAMES:%=$(BIN_DIR)/%)

# Librería
UTILS_LIB = $(BUILD_DIR)/libutils.a

# Targets principales (se crean cuando existan archivos main)
SERVER_TARGET = $(BIN_DIR)/socks5d
CLIENT_TARGET = $(BIN_DIR)/socks5_client

# Target por defecto
.PHONY: all
all: $(UTILS_LIB) tests

# Paths de include
INCLUDE_PATHS = -I$(UTILS_INCLUDE_DIR)
# Agregar includes de server y client cuando existan
ifneq ($(wildcard $(SERVER_INCLUDE_DIR)/.),)
    INCLUDE_PATHS += -I$(SERVER_INCLUDE_DIR)
endif
ifneq ($(wildcard $(CLIENT_INCLUDE_DIR)/.),)
    INCLUDE_PATHS += -I$(CLIENT_INCLUDE_DIR)
endif

# Crear directorios
$(OBJ_DIR) $(BIN_DIR) $(OBJ_DIR)/utils $(OBJ_DIR)/server $(OBJ_DIR)/client:
	mkdir -p $@

# Construir librería de utilidades
.PHONY: utils
utils: $(UTILS_LIB)

$(UTILS_LIB): $(UTILS_OBJECTS) | $(BUILD_DIR)
	ar rcs $@ $^

# Compilar archivos objeto de utils
$(OBJ_DIR)/utils/%.o: $(UTILS_DIR)/%.c | $(OBJ_DIR)/utils
	$(CC) $(CFLAGS) $(INCLUDE_PATHS) -c $< -o $@

# Compilar archivos objeto del servidor (cuando existan)
$(OBJ_DIR)/server/%.o: $(SERVER_DIR)/%.c | $(OBJ_DIR)/server
	$(CC) $(CFLAGS) $(INCLUDE_PATHS) -c $< -o $@

# Compilar archivos objeto del cliente (cuando existan)
$(OBJ_DIR)/client/%.o: $(CLIENT_DIR)/%.c | $(OBJ_DIR)/client
	$(CC) $(CFLAGS) $(INCLUDE_PATHS) -c $< -o $@

# Construir todos los tests
.PHONY: tests
tests: $(UTILS_LIB) $(TEST_EXECUTABLES)

$(BIN_DIR)/%_test: $(TEST_DIR)/%_test.c $(UTILS_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDE_PATHS) -I$(UTILS_DIR) $< $(UTILS_LIB) $(TEST_LIBS) -o $@

# Construir servidor (cuando exista archivo main)
.PHONY: server
server: $(UTILS_LIB) $(SERVER_TARGET)

$(SERVER_TARGET): $(SERVER_OBJECTS) $(UTILS_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

# Construir cliente (cuando exista archivo main)  
.PHONY: client
client: $(UTILS_LIB) $(CLIENT_TARGET)

$(CLIENT_TARGET): $(CLIENT_OBJECTS) $(UTILS_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

# Limpiar archivos compilados
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Limpiar y reconstruir
.PHONY: rebuild
rebuild: clean all

# Prevenir que se eliminen archivos intermedios
.PRECIOUS: $(OBJ_DIR)/%.o

# Crear directorio de compilación
$(BUILD_DIR):
	mkdir -p $@