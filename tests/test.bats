setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'
    load 'test_helper/bats-file/load'
    DATA="/data"
    ENCRYPTED_IMAGE="${DATA}/crypty.img"
    PATH="/test/bin:$PATH"
}

@test "have encrypted disk image" {
    assert_file_exist "$ENCRYPTED_IMAGE"
    #run strings "$ENCRYPTED_IMAGE"
    #refute_output --partial "plain"
}

@test "help output by default" {
    run tpm-luks
    assert_output --partial "Usage: tpm-luks [OPTIONS] <COMMAND>"
}
