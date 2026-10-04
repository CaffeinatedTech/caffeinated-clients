TAILWINDCSS ?= tailwindcss
VERSION ?= dev

.PHONY: all build css test vet fmt run

all: build

# Compile the one CSS file. web/static/app.css is committed so a plain
# `go build`/`go test` works offline without the Tailwind CLI; this target
# refreshes it after template changes.
css:
	$(TAILWINDCSS) -i web/input.css -o web/static/app.css --minify

build: css
	go build ./...

test: css
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

run: css
	go run .
