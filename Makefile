.PHONY: all build test vet fmt check runner integration clean

all: check build

build:
	mkdir -p bin
	go build -trimpath -ldflags "-s -w" -o bin/behaviorlock ./cmd/behaviorlock

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal schemas

check:
	test -z "$$(gofmt -l cmd internal schemas)"
	go vet ./...
	go test -race ./...
	node --test runner/*.test.mjs
	sh -n runner/*.sh scripts/*.sh testdata/tracer-failure/*.sh
	command -v shellcheck >/dev/null
	shellcheck runner/*.sh scripts/*.sh testdata/tracer-failure/*.sh
	./scripts/test-dco.sh
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
	jq empty config/*.json schemas/*.json testdata/npm-fixture/seed/*.json testdata/npm-fixture/seed/node_modules/behaviorlock-fixture/*.json

runner:
	docker build --pull=false --tag behaviorlock-runner:dev runner

integration: runner
	./scripts/integration-runner.sh

clean:
	go clean
	trash bin 2>/dev/null || true
