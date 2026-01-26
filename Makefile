.PHONY: all

all: fmt test check build helm-lint

build:
	go build -o bin/goons ./cmd/goons

local:
	env bash -c 'source ./.env; go run ./cmd/goons'

test:
	go test -cover ./...

check: staticcheck vulncheck deadcode

staticcheck:
	go tool honnef.co/go/tools/cmd/staticcheck ./...

vulncheck:
	go tool golang.org/x/vuln/cmd/govulncheck ./...

deadcode:
	go tool golang.org/x/tools/cmd/deadcode -test ./...

fmt:
	go tool mvdan.cc/gofumpt -w ./

helm-lint:
	helm lint --strict ./charts
