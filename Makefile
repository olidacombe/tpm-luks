.PHONY: init readme swtpm swtpm-image

init:
	cargo install cargo-readme

readme:
	cargo readme > README.md

swtpm-image:
	cd tests \
	&& docker build -t swtpm -f Dockerfile-swtpm . \

swtpm: swtpm-image
	-docker kill swtpm
	docker run -d --rm --name swtpm -p 2321:2321 -p 2322:2322 swtpm
