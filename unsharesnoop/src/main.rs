use core::time::Duration;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Result};
use chrono::{Local, SecondsFormat};
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use structopt::StructOpt;
#[macro_use]
extern crate bitflags;

mod bpf;
use bpf::*;

bitflags! {
    struct CloneFlags: u64 {
        const CLONE_NEWNS = 0x00020000;
        const CLONE_NEWCGROUP = 0x02000000;
        const CLONE_NEWUTS = 0x04000000;
        const CLONE_NEWIPC = 0x08000000;
        const CLONE_NEWUSER = 0x10000000;
        const CLONE_NEWPID = 0x20000000;
        const CLONE_NEWNET = 0x40000000;
        const CLONE_NEWTIME = 0x00000080;
    }
}

#[derive(Debug, StructOpt)]
struct Command {
    /// Showing results that are failed
    #[structopt(short = "a", long = "all")]
    show_failed: bool,
}

#[repr(C)]
#[derive(Default, Debug)]
struct Event {
    pub pid: u32,
    pub flags: u64,
    pub ret: i32,
    pub comm: [u8; 16],
}
unsafe impl Plain for Event {}

fn handle_event(_cpu: i32, data: &[u8]) {
    let now = Local::now();
    let mut event: Event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short or invalid");

    let comm = str::from_utf8(&event.comm).unwrap().trim_end_matches('\0');
    let flags = CloneFlags::from_bits_truncate(event.flags);

    println!(
        "{:20} {:6} {:<18} {:3} {:#010x} {:?}",
        now.to_rfc3339_opts(SecondsFormat::Secs, true),
        event.pid,
        comm,
        event.ret,
        event.flags,
        flags,
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("[!] Lost {} events on CPU {}", count, cpu);
}

fn rlimit_setup() -> Result<()> {
    use libc::{perror, rlimit, setrlimit};
    let rlim = rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    unsafe {
        if setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
            perror("setrlimit(RLIMIT_MEMLOCK)\0".as_ptr() as *const libc::c_char);
            bail!("Failed to increase rlimit");
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let opts: Command = Command::from_args();
    rlimit_setup()?;
    let skel_builder = UnsharesnoopSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;

    if opts.show_failed {
        open_skel.rodata().targ_failed = 1u8;
    } else {
        open_skel.rodata().targ_failed = 0u8;
    }
    let mut skel = open_skel.load()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    println!(
        "{:20} {:6} {:18} {:3} {:10} {}",
        "TIME", "TID", "COMM", "RET", "FLAGS", "FLAGS(human)"
    );
    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    while running.load(Ordering::SeqCst) {
        if let Err(e) = perf.poll(Duration::from_millis(100)) {
            use nix::errno::Errno;

            if let libbpf_rs::Error::System(errno) = e {
                let e = Errno::from_i32(errno);
                match e {
                    // Ignore EINTER
                    Errno::EINTR => (),
                    _ => bail!("Error: {:?}", e),
                }
            } else {
                bail!("Error: {:?}", e);
            }
        }
    }
    println!("");
    println!("Stopped");

    Ok(())
}
