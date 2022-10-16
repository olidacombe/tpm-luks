setup_file() {
    DATA="/data"
    ENCRYPTED_IMAGE="${DATA}/crypty.img"
    LOOPDEVICE=$(losetup -f)
    MNT=/test/mnt
    PATH="/test/bin:$PATH"
    PASSPHRASE=${PASSPHRASE:-insecure}

    mkdir -p $MNT >&2
    losetup $LOOPDEVICE $ENCRYPTED_IMAGE >&2

    export DATA
    export ENCRYPTED_IMAGE
    export LOOPDEVICE
    export MNT
    export PATH
    export PASSPHRASE
}

teardown() {
    umount $MNT || true
}

teardown_file() {
    umount $MNT
    losetup -d $LOOPDEVICE
}

setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'
    load 'test_helper/bats-file/load'
}

@test "have encrypted disk image" {
    assert_file_exist "$ENCRYPTED_IMAGE"
    #run strings "$ENCRYPTED_IMAGE"
    #refute_output --partial "plain"
}

@test "binary is statically linked" {
    run ldd $(which tpm-luks)
    assert_output --partial "Not a valid dynamic program"
}

@test "help output by default" {
    run tpm-luks
    assert_output --partial "Usage: tpm-luks [OPTIONS] <COMMAND>"
}

@test "outputs PCR digest" {
    skip "not working yet"
    run tpm-luks digest
    assert_success
}

@test "seals and unseals" {
    skip "todo"
}
