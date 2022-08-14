.PHONY: ci-image dev dev-image dev-local init readme swtpm swtpm-image
init:
	cargo install cargo-readme

readme:
	cargo readme > README.md

swtpm-image:
	docker build -t olidacombe/swtpm -f tests/Dockerfile-swtpm tests

swtpm: swtpm-image
	-docker kill swtpm
	docker run -d --rm --name swtpm -p 2321:2321 -p 2322:2322 olidacombe/swtpm

ci-image:
	docker build -t olidacombe/tpm-luks-ci -f Dockerfile-ci .

dev-image: ci-image swtpm
	docker build -t tpm-luks-dev -f Dockerfile-dev .

dev: swtpm dev-image
	docker run --rm -it --name tpm-luks-dev -e TCTI=swtpm:port=2321,host=host.docker.internal -v $${PWD}:/tmp/src -w /tmp/src tpm-luks-dev cargo watch -x test

dev-local: swtpm
	TCTI=swtpm:port=2321,host=127.0.0.1 cargo watch -x test

sync-%:
	fswatch -o . | xargs -n1 -I{} ./sync.sh $*/
