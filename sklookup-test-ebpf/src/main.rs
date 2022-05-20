#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, sk_lookup},
    maps::SockMap,
    programs::SkLookupContext,
    bindings::sk_action,
};
use aya_log_ebpf::info;

#[map]
static mut REDIR: SockMap = SockMap::with_max_entries(1, 0);

const DST_PORT: u32 = 7007;

#[sk_lookup(name="sklookup_test")]
pub fn sklookup_test(ctx: SkLookupContext) -> u32 {
    match unsafe { try_sklookup_test(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_sklookup_test(ctx: SkLookupContext) -> Result<u32, u32> {
    let local_port = (*ctx.lookup).local_port;
    info!(&ctx, "received a socket lookup for the netns. local port: {}, dst port: {}", local_port, DST_PORT);
    if local_port != DST_PORT {
        return Err(sk_action::SK_PASS);
    }
    REDIR.redirect_sk_lookup(&ctx, 0, 0).map_err(|_| sk_action::SK_PASS )?;
    Ok(sk_action::SK_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
