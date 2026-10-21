//! DeepSeek adapter (strategy 3, broker). See [`adapter`]'s module docs
//! -- this crate manages proxy-grant *records* only; the service that
//! actually forwards traffic and injects the real key does not exist yet.

pub mod adapter;

pub use adapter::DeepSeekAdapter;
