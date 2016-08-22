pub mod ethernet;

pub mod ipv4;

#[cfg(all(not(feature = "unit-tests"), not(feature = "integration-tests")))]
#[test]
fn tests_should_be_run_with_features() {
    let msg = "\n
        ===========================\n
        To run unit tests:\n
        \tcargo test --features \"unit-tests\".\n
        Integration tests:\n
        \tcargo test --features \"integration-tests\"\n
        ===========================\n";
    panic!(msg);
}
