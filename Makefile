VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# ROOT_KEYS: the job-signing root public key(s), id:base64[,id:base64].
# A build without them accepts no jobs (automatic runs stay off).
ROOT_KEYS ?=
LDFLAGS   := -s -w -X main.version=$(VERSION) -X github.com/adamgyulavari/upkeeper-cli/protocol.rootKeys=$(ROOT_KEYS)
BIN       := bin

.PHONY: build build-dev keys test vet check clean

# Static agent binaries for linux/amd64 and linux/arm64 (no CGO).
build:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/upkeeper_linux_amd64 ./cmd/upkeeper
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/upkeeper_linux_arm64 ./cmd/upkeeper
	cd $(BIN) && sha256sum upkeeper_linux_amd64 upkeeper_linux_arm64 > checksums.txt

# Development build that also trusts the TEST root key (its private key is
# public). Never install it on a server you care about.
build-dev:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS) -X github.com/adamgyulavari/upkeeper-cli/protocol.allowTestRoot=yes' -o $(BIN)/upkeeper_dev_linux_amd64 ./cmd/upkeeper

# The offline key tool (root key, online keys, certificates).
keys:
	@mkdir -p $(BIN)
	go build -trimpath -o $(BIN)/upkeeper-keys ./cmd/upkeeper-keys

vet:
	go vet ./...

test:
	go test ./...

check: vet test

clean:
	rm -rf $(BIN) dist
