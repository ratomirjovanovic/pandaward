VERSION ?= 0.1.0-dev
LDFLAGS := -s -w -X github.com/ratomirjovanovic/pensec/internal/version.Version=$(VERSION)

.PHONY: build test vet validate dist

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pensec$(if $(filter Windows_NT,$(OS)),.exe,) ./cmd/pensec

test:
	go test ./...

vet:
	gofmt -l . && go vet ./...

validate: build
	claude plugin validate .

dist:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pensec-linux-amd64 ./cmd/pensec
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pensec-linux-arm64 ./cmd/pensec
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pensec-darwin-arm64 ./cmd/pensec
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pensec-darwin-amd64 ./cmd/pensec
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pensec-windows-amd64.exe ./cmd/pensec
	cd dist && sha256sum * > SHA256SUMS
