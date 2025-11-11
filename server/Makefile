APP_NAME := server
DIST_DIR := dist

build:
	mkdir -p $(DIST_DIR)
	go build -o $(DIST_DIR)/$(APP_NAME) .

run: build
	./$(DIST_DIR)/$(APP_NAME)

clean:
	rm -rf $(DIST_DIR)
