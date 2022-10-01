#!/usr/bin/env bash

set -xeuo pipefail

DISK=crypy.img
LUKS_NAME=crypty
LUKS_DEV=/dev/mapper/$LUKS_NAME
MNT=mnt
KEY_FILE=disk.key

RUST_LOG=debug

teardown() {
	sudo umount $MNT || true
	sudo cryptsetup remove $LUKS_NAME || true
	sudo losetup -d $loopdevice || true
}
trap teardown EXIT

setup() {
	rm -f $DISK
	fallocate -l 20MiB $DISK
	dd if=/dev/urandom of=$KEY_FILE bs=1 count=32
	loopdevice=$(losetup -f)
	sudo losetup $loopdevice $DISK
	sudo cryptsetup luksFormat -q --key-file=$KEY_FILE $loopdevice

	sudo cryptsetup luksOpen --key-file=$KEY_FILE $loopdevice $LUKS_NAME
	sudo mkfs.ext4 -j $LUKS_DEV
	mkdir -p $MNT
	sudo mount $LUKS_DEV $MNT

	sudo touch ${MNT}/plain.txt
	sudo chmod 777 ${MNT}/plain.txt
	sudo echo "This is my plain text" > ${MNT}/plain.txt
}

seal() {
	setup
	sudo $tpm_luks seal $loopdevice
	teardown
}

unseal() {
	loopdevice=$(losetup -f)
	sudo losetup $loopdevice $DISK
	sudo $tpm_luks unseal $loopdevice $LUKS_NAME
	mount $LUKS_DEV $MNT
	ls mnt
	teardown
}

cargo build --release
tpm_luks=target/release/tpm-luks

seal
unseal
