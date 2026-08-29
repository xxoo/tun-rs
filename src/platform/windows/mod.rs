mod device;
mod dns;
pub(crate) mod ffi;
#[cfg(any(
    feature = "interruptible",
    feature = "async_tokio",
    feature = "async_io"
))]
mod interrupt;
mod netsh;
mod tap;
mod tun;
#[cfg(any(
    feature = "interruptible",
    feature = "async_tokio",
    feature = "async_io"
))]
pub use interrupt::InterruptEvent;

pub use device::DeviceImpl;
pub use tun::{remove_wintun_adapter_exact, wintun_adapter_exists_exact};
