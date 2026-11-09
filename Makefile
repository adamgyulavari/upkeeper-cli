VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin

.PHONY: build test vet check clean

# Static agent binaries for linux/amd64 and linux/arm64 (no CGO).
build:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/upkeeper_linux_amd64 ./cmd/upkeeper
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/upkeeper_linux_arm64 ./cmd/upkeeper
	cd $(BIN) && sha256sum upkeeper_linux_amd64 upkeeper_linux_arm64 > checksums.txt

vet:
	go vet ./...

test:
	go test ./...

check: vet test

clean:
	rm -rf $(BIN) dist
