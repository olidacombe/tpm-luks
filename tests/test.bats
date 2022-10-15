setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'
    DATA="/data"
    ENCRYPTED_IMAGE="${DATA}/crypty.img"
}

@test "have encrypted disk image" {
    assert_exist "$ENCRYPTED_IMAGE"
    run strings "$ENCRYPTED_IMAGE"
    refute_output "plain"
}
