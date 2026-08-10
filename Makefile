.PHONY: all build test vet fmt check benchmark usability runner integration clean

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
	sh -n runner/*.sh scripts/*.sh testdata/control-runner/*.sh testdata/resource-fixture/seed/node_modules/behaviorlock-resource-fixture/*.sh testdata/tracer-death/*.sh testdata/tracer-failure/*.sh
	command -v shellcheck >/dev/null
	shellcheck runner/*.sh scripts/*.sh testdata/control-runner/*.sh testdata/resource-fixture/seed/node_modules/behaviorlock-resource-fixture/*.sh testdata/tracer-death/*.sh testdata/tracer-failure/*.sh
	./scripts/test-dco.sh
	./scripts/test-release-proof-ledger.sh
	./scripts/check-benchmark.sh
	go run ./cmd/doc-check --root .
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
	jq empty benchmark/*.json config/*.json docs/templates/*.json schemas/*.json testdata/npm-fixture/seed/*.json testdata/npm-fixture/seed/node_modules/behaviorlock-fixture/*.json testdata/resource-fixture/seed/*.json testdata/resource-fixture/seed/node_modules/behaviorlock-resource-fixture/*.json testdata/sinkhole-fixture/seed/*.json testdata/sinkhole-fixture/seed/node_modules/behaviorlock-sinkhole-fixture/*.json

benchmark:
	./scripts/check-benchmark.sh

usability:
	./scripts/usability-check.sh

runner:
	docker build --pull=false --tag behaviorlock-runner:dev runner

integration: runner
	./scripts/integration-runner.sh

clean:
	go clean
	trash bin 2>/dev/null || true
