teardown() {
    umount $MNT || true
    losetup -d $LOOPDEVICE || true
    cryptsetup close $CRYPT_DEV_NAME || true
}

setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'
    load 'test_helper/bats-file/load'

    DATA="/data"
    ENCRYPTED_IMAGE="${DATA}/crypty.img"
    LOOPDEVICE=$(losetup -f)
    CRYPT_DEV_NAME=crypty
    LUKS_DEV="/dev/mapper/$CRYPT_DEV_NAME"
    MNT=/test/mnt
    PATH="/test/bin:$PATH"
    PASSPHRASE=${PASSPHRASE:-insecure}
    RUST_BACKTRACE=full
    RUST_LOG=debug

    mkdir -p $MNT >&2
    losetup $LOOPDEVICE $ENCRYPTED_IMAGE >&2
}

@test "have encrypted disk image" {
    assert_file_exist "$ENCRYPTED_IMAGE"
    #run strings "$ENCRYPTED_IMAGE"
    #refute_output --partial "plain"
}

@test "binary is statically linked" {
    skip "we are not building a static binary which speaks \`swtpm\` yet"
    run ldd $(which tpm-luks)
    assert_output --partial "Not a valid dynamic program"
}

@test "help output by default" {
    run tpm-luks
    assert_output --partial "Usage: tpm-luks [OPTIONS] <COMMAND>"
}

@test "outputs PCR digest" {
    run tpm-luks digest
    assert_success
    assert_output --partial "Current PCR Digest: "
}

@test "seals and unseals" {
    run tpm-luks seal "$LOOPDEVICE"
    assert_success
    run tpm-luks unseal "$LOOPDEVICE" "$CRYPT_DEV_NAME"
    assert_success
    run mount -t ext4 "$LUKS_DEV" "$MNT"
    assert_success
    assert_file_exist "${MNT}/plain.txt"
}
