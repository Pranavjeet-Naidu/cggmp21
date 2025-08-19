#![no_std]

pub use cggmp24_keygen;
pub use key_share;

#[panic_handler]
fn panic(_panic: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
