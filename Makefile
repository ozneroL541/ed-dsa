.PHONY: run build clean

BIN_DIR		:=bin
APP_NAME	:=ed-dsa
BIN			:=$(BIN_DIR)/$(APP_NAME)
LIB_ARCHIVE := $(BIN_DIR)/$(APP_NAME).a

run: build
	@./$(BIN)

build: download_deps
	@mkdir -p $(BIN_DIR)
	go build -buildmode=archive -o $(LIB_ARCHIVE) $(LIB_PKG)

download_deps:
	@go get filippo.io/edwards25519

test:
	@go test ./...

clean:
	@rm -rf $(BIN_DIR)
