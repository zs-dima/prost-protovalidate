use prost_reflect::DescriptorPool;
use std::sync::LazyLock;

#[allow(clippy::unwrap_used)]
pub static DESCRIPTOR_POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(
        include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin")).as_ref(),
    )
    .unwrap()
});

include!(concat!(env!("OUT_DIR"), "/buf.validate.rs"));
