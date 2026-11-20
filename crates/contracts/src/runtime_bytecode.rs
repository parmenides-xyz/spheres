use crate::{SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS};
use alloy_primitives::{Address, Bytes};

const SPHERE_INBOX: &[u8] = include_bytes!("../assets/runtime/SphereInbox.bin");
const SPHERE_OUTBOX: &[u8] = include_bytes!("../assets/runtime/SphereOutbox.bin");

/// Binds the Arc portal to the deployed Sphere inbox and outbox bytecode.
pub fn sphere_runtime_contracts(portal_address: Address) -> [(Address, Bytes); 2] {
    let mut replacement = [0u8; 32];
    replacement[12..].copy_from_slice(portal_address.as_slice());
    [
        (SPHERE_INBOX_ADDRESS, SPHERE_INBOX, 4),
        (SPHERE_OUTBOX_ADDRESS, SPHERE_OUTBOX, 2),
    ]
    .map(|(address, template, expected_count)| {
        let mut code = template.to_vec();
        let count = patch_bytes(&mut code, &[0; 32], &replacement);
        assert_eq!(
            count, expected_count,
            "unexpected portal immutable count in {address}"
        );
        (address, code.into())
    })
}

/// Replaces all non-overlapping occurrences of `needle` with `replacement` in `buf`.
///
/// Both must have the same length. Returns the number of replacements made.
fn patch_bytes(buf: &mut [u8], needle: &[u8], replacement: &[u8]) -> usize {
    assert_eq!(needle.len(), replacement.len());
    let len = needle.len();
    let mut count = 0;
    let mut i = 0;
    while i + len <= buf.len() {
        if buf[i..i + len] == *needle {
            buf[i..i + len].copy_from_slice(replacement);
            count += 1;
            i += len;
        } else {
            i += 1;
        }
    }
    count
}
