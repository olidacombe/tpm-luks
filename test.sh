#!/usr/bin/env bash

set -xeuo pipefail

LUKS_NAME=crypty
DISK=${LUKS_NAME}.img
LUKS_DEV=/dev/mapper/$LUKS_NAME
MNT=mnt

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
	export PASSPHRASE=$(openssl rand -base64 33)
	loopdevice=$(losetup -f)
	sudo losetup $loopdevice $DISK
	echo -n "$PASSPHRASE" | sudo cryptsetup luksFormat -q $loopdevice -
	echo -n "$PASSPHRASE" | sudo cryptsetup luksOpen $loopdevice $LUKS_NAME -
	sudo mkfs.ext4 -j $LUKS_DEV
	mkdir -p $MNT
	sudo mount $LUKS_DEV $MNT

	sudo touch ${MNT}/plain.txt
	sudo chmod 777 ${MNT}/plain.txt
	sudo echo "This is my plain text" > ${MNT}/plain.txt
}

seal() {
	setup
	echo "using existing $PASSPHRASE to add second key"
	sudo PASSPHRASE=$PASSPHRASE $tpm_luks seal $loopdevice
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

if [ -n ${BUILD+x} ]; then
	cargo build --release
	tpm_luks=target/release/tpm-luks
else
	tpm_luks=./tpm-luks
fi

seal
unseal
