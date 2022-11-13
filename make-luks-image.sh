#!/usr/bin/env bash

set -xeuo pipefail

LUKS_NAME=${1:-crypty}
DISK=${LUKS_NAME}.img
LUKS_DEV=/dev/mapper/$LUKS_NAME
MNT=mnt

teardown() {
	umount $MNT || true
	cryptsetup remove $LUKS_NAME || true
	losetup -d $loopdevice || true
}
trap teardown EXIT

fallocate -l 20MiB $DISK
ls -lh $DISK
export PASSPHRASE=${PASSPHRASE:-$(openssl rand -base64 33)}
loopdevice=$(losetup -f)
losetup $loopdevice $DISK
echo -n "$PASSPHRASE" | cryptsetup luksFormat -q $loopdevice -
echo -n "$PASSPHRASE" | cryptsetup luksOpen $loopdevice $LUKS_NAME -
mkfs.ext4 -j $LUKS_DEV
mkdir -p $MNT
mount $LUKS_DEV $MNT

touch ${MNT}/plain.txt
chmod 777 ${MNT}/plain.txt
echo "This is my plain text" > ${MNT}/plain.txt
