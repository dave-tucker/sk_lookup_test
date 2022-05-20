use aya::maps::{MapRefMut, SockMap};
use aya::programs::SkLookup;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::fs::File;
use std::os::unix::prelude::AsRawFd;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/proc/self/ns/net")]
    netns_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/sklookup-test"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sklookup-test"
    ))?;
    BpfLogger::init(&mut bpf)?;
    let mut sock_map = SockMap::<MapRefMut>::try_from(bpf.map_mut("REDIR")?)?;
    let prog: &mut SkLookup = bpf.program_mut("sklookup_test").unwrap().try_into()?;
    prog.load()?;

    let netns = File::open(opt.netns_path)?;
    prog.attach(netns)?;

    let listener = TcpListener::bind("127.0.0.1:41234").await?;
    let listener_fd = listener.as_raw_fd();
    sock_map.set(0, &listener_fd, 0)?;
    info!("Server Listening on {}", listener.local_addr().unwrap());
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            loop {
                let n = socket
                    .read(&mut buf)
                    .await
                    .expect("failed to read data from socket");

                if n == 0 {
                    return;
                }

                socket
                    .write_all(&buf[0..n])
                    .await
                    .expect("failed to write data to socket");
            }
        });
    }
}
