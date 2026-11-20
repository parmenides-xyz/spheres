use alloy_signer_local::PrivateKeySigner;

pub(crate) fn parse_private_key(private_key: &str) -> eyre::Result<PrivateKeySigner> {
    Ok(private_key
        .strip_prefix("0x")
        .unwrap_or(private_key)
        .parse()?)
}
