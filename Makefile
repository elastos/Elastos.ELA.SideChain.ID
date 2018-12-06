GOFMT=gofmt
VERSION := $(shell git describe --abbrev=4 --dirty --always --tags)

BUILD=go build -ldflags "-X main.Version=$(VERSION) -X 'main.GoVersion=`go version`'" #-race

all:
	$(BUILD) -o did config.go log.go main.go
	$(BUILD) -o did_wallet_cli config.go did_wallet_cli.go
	$(BUILD) -o did_wallet config.go did_wallet_log.go did_wallet.go

format:
	$(GOFMT) -w main.go

clean:
	rm -rf *.8 *.o *.out *.6
