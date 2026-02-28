use prost_reflect::DescriptorPool;
use std::sync::LazyLock;

static DESCRIPTOR_POOL_DECODE: LazyLock<(DescriptorPool, Option<String>)> = LazyLock::new(|| {
    match DescriptorPool::decode(
        include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin")).as_ref(),
    ) {
        Ok(pool) => (pool, None),
        Err(err) => (DescriptorPool::new(), Some(err.to_string())),
    }
});

pub static DESCRIPTOR_POOL: LazyLock<DescriptorPool> =
    LazyLock::new(|| DESCRIPTOR_POOL_DECODE.0.clone());

#[must_use]
pub fn descriptor_pool_decode_error() -> Option<&'static str> {
    DESCRIPTOR_POOL_DECODE.1.as_deref()
}

include!(concat!(env!("OUT_DIR"), "/buf.validate.rs"));
