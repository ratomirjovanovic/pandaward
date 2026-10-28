VERSION ?= 0.1.2-dev
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
	sh packaging/build-release.sh $(VERSION) dist
