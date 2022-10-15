setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'
    load 'test_helper/bats-file/load'
    DATA="/data"
    ENCRYPTED_IMAGE="${DATA}/crypty.img"
}

@test "have encrypted disk image" {
    assert_exist "$ENCRYPTED_IMAGE"
    run strings "$ENCRYPTED_IMAGE"
    refute_output "plain"
}

@test "help output by default" {
    run tpm-luks
    assert_output "Usage: tpm-luks [OPTIONS] <COMMAND>"
}
