//! Resource limits: raising RLIMIT_NOFILE never lowers the soft limit.

use rlimit::Resource;
use svpn::limits::*;

#[test]
fn raise_never_lowers_the_soft_limit() {
    let before = Resource::NOFILE.get().unwrap().0;
    raise_and_report();
    let after = Resource::NOFILE.get().unwrap().0;
    assert!(after >= before);
}
