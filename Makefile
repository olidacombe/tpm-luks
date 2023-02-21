.PHONY: ci-image dev dev-image dev-local help init readme swtpm swtpm-image
.DEFAULT_GOAL := help

IMAGE_BASE ?= olidacombe

init: ## install required packages
	cargo install cargo-readme

readme: ## render README.md from crate-level rustdoc
	cargo readme > README.md

swtpm-image: ## build software tpm docker image for testing against
	docker build -t $(IMAGE_BASE)/swtpm -f tests/Dockerfile-swtpm tests

swtpm: swtpm-image ## run software tpm service for test interaction
	-docker kill swtpm
	docker run -d --rm --name swtpm -p 2321:2321 -p 2322:2322 $(IMAGE_BASE)/swtpm
	sleep 2

ci-image: ## build docker image with necessary dependencies to run CI tasks
	docker build -t $(IMAGE_BASE)/tpm-luks-ci -f Dockerfile-ci .

dev-image: ci-image swtpm ## build docker image for use as a development environment
	docker build -t tpm-luks-dev -f Dockerfile-dev .

dev: swtpm dev-image ## run cargo test (with `cargo watch`) inside a dev container
	-docker kill tpm-luks-dev
	docker run --rm -it --name tpm-luks-dev -e TCTI=swtpm:port=2321,host=host.docker.internal -v $${PWD}:/tmp/src -w /tmp/src tpm-luks-dev cargo watch -x test

dev-local: swtpm ## run cargo test (with `cargo watch`) locally against `swtpm` container - if you're already on a suitable system like linux
	TCTI=swtpm:port=2321,host=127.0.0.1 cargo watch -x test

dev-raw: ## run cargo test (with `cargo watch`) locally - if you're already on a suitable system like linux
	TCTI=device:/dev/tpmrm0 cargo watch -x test

help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

sync-%: ## watch and sync files to test instance, e.g. `make sync-my-test-machine`
	fswatch -o . | xargs -n1 -I{} ./sync.sh $*/

build:
	docker build -t $(IMAGE_BASE)/tpm-luks .

push:
	docker push $(IMAGE_BASE)/tpm-luks
