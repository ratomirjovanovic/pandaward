VERSION ?= 0.2.0-dev
LDFLAGS := -s -w -X github.com/ratomirjovanovic/pandaward/internal/version.Version=$(VERSION)

.PHONY: build test vet validate dist

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pandaward$(if $(filter Windows_NT,$(OS)),.exe,) ./cmd/pandaward

test:
	go test ./...

vet:
	gofmt -l . && go vet ./...

validate: build
	claude plugin validate .

dist:
	sh packaging/build-release.sh $(VERSION) dist
