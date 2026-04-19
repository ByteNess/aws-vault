VERSION=$(shell git describe --tags --candidates=1 --dirty)
BUILD_FLAGS=-ldflags="-s -w -X main.Version=$(VERSION)" -trimpath
CERT_ID ?= Developer ID Application: ByteNess (R)
SRC=$(shell find . -name '*.go') go.mod
INSTALL_DIR ?= ~/bin
.PHONY: binaries clean release install snapshot run

ifeq ($(shell uname), Darwin)
aws-vault: $(SRC)
	go build -ldflags="-s -w -X main.Version=$(VERSION)" -o $@ .
	codesign --options runtime --timestamp --sign "$(CERT_ID)" $@
else
aws-vault: $(SRC)
	go build -ldflags="-s -w -X main.Version=$(VERSION)" -o $@ .
endif

install: aws-vault
	mkdir -p $(INSTALL_DIR)
	rm -f $(INSTALL_DIR)/aws-vault
	cp -a ./aws-vault $(INSTALL_DIR)/aws-vault

binaries: aws-vault-linux-amd64 aws-vault-linux-arm64 aws-vault-linux-ppc64le aws-vault-linux-arm7 aws-vault-darwin-amd64 aws-vault-darwin-arm64 aws-vault-windows-386.exe aws-vault-windows-arm64.exe aws-vault-freebsd-amd64
dmgs: aws-vault-darwin-amd64.dmg aws-vault-darwin-arm64.dmg

clean:
	rm -rf ./aws-vault ./aws-vault-*-* ./SHA256SUMS dist/

snapshot: clean ## Build local snapshot
	goreleaser build --clean --snapshot --single-target

run:
	go run .

test: ## Run tests
	go test -v ./...

fmt: **/*.go ## Formt Golang code
	go fmt ./...

lint:
	golint ./...

vet:
	go vet -all ./...

release: binaries SHA256SUMS

	@echo "\nTo create a new release run:\n\n    gh release create --title $(VERSION) $(VERSION) \
	aws-vault-darwin-amd64.dmg \
	aws-vault-darwin-arm64.dmg \
	aws-vault-freebsd-amd64 \
	aws-vault-linux-amd64 \
	aws-vault-linux-arm64 \
	aws-vault-linux-arm7 \
	aws-vault-linux-ppc64le \
	aws-vault-windows-386.exe \
	aws-vault-windows-arm64.exe \
	SHA256SUMS\n"

	@echo "\nTo update homebrew-cask run:\n\n    brew bump-cask-pr --version $(shell echo $(VERSION) | sed 's/v\(.*\)/\1/') aws-vault\n"

ubuntu-latest: aws-vault-linux-amd64 aws-vault-linux-arm64 aws-vault-linux-ppc64le aws-vault-windows-amd64.exe aws-vault-windows-arm64.exe aws-vault-freebsd-amd64

macos-latest: aws-vault-darwin-amd64 aws-vault-darwin-arm64

aws-vault-darwin-amd64: $(SRC)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 SDKROOT=$(shell xcrun --sdk macosx --show-sdk-path) go build $(BUILD_FLAGS) -o $@ .

aws-vault-darwin-arm64: $(SRC)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 SDKROOT=$(shell xcrun --sdk macosx --show-sdk-path) go build $(BUILD_FLAGS) -o $@ .

aws-vault-freebsd-amd64: $(SRC)
	GOOS=freebsd GOARCH=amd64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-linux-amd64: $(SRC)
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-linux-arm64: $(SRC)
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-linux-ppc64le: $(SRC)
	GOOS=linux GOARCH=ppc64le go build $(BUILD_FLAGS) -o $@ .

aws-vault-linux-arm7: $(SRC)
	GOOS=linux GOARCH=arm GOARM=7 go build $(BUILD_FLAGS) -o $@ .

aws-vault-windows-386.exe: $(SRC)
	GOOS=windows GOARCH=386 go build $(BUILD_FLAGS) -o $@ .

aws-vault-windows-amd64.exe: $(SRC)
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-windows-arm64.exe: $(SRC)
	GOOS=windows GOARCH=arm64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-darwin-amd64.dmg: aws-vault-darwin-amd64
	./bin/create-dmg aws-vault-darwin-amd64 $@

aws-vault-darwin-arm64.dmg: aws-vault-darwin-arm64
	./bin/create-dmg aws-vault-darwin-arm64 $@

aws-vault_sha256_checksums.txt:
	sha256sum \
	  aws-vault-* \
	    > $@

SHA256SUMS: binaries dmgs
	shasum -a 256 \
	  aws-vault-darwin-amd64.dmg \
	  aws-vault-darwin-arm64.dmg \
	  aws-vault-freebsd-amd64 \
	  aws-vault-linux-amd64 \
	  aws-vault-linux-arm64 \
	  aws-vault-linux-arm7 \
	  aws-vault-linux-ppc64le \
	  aws-vault-windows-386.exe \
	  aws-vault-windows-arm64.exe \
	    > $@
