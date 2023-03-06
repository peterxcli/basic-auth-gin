.PHONY: build clean tool lint help

all: run

run: build https
	./basic-auth-gin

swag:
	swag init

https:
	#mkdir -p cert && sh generate-certificate.sh

build: swag
	@go build -v .

test:
	go test -v -cover=true ./...


tool:
	go vet ./...; true
	gofmt -w .

lint:
	golint ./...

clean:
	rm -rf basic-auth-gin
	go clean -i .

help:
	@echo "make: compile packages and dependencies"
	@echo "make tool: run specified go tool"
	@echo "make lint: golint ./..."
	@echo "make clean: remove object files and cached files"

install:
	go install
	go install github.com/swaggo/swag/cmd/swag@latest
