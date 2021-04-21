use anyhow::Result;
use libbpf_rs::MapFlags;
use plain::Plain;
use structopt::StructOpt;
use textplots::{Chart, Plot, Shape};

use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

mod bpf;
use bpf::*;

#[derive(Debug, StructOpt)]
struct Command {
    /// Target cgroup directory to track
    #[structopt(short = "c", value_name = "CGROUP_DIR")]
    cgroup_dir: Option<String>,
    /// Show operation count instead of bytesize
    #[structopt(long = "count")]
    show_count: bool,
    /// Show avarage operation bytesize per period
    #[structopt(long = "avg")]
    show_avg: bool,
    /// Summrization period (ms)
    #[structopt(short = "t", long = "period", default_value = "1000")]
    period: u64,
}

#[repr(C)]
#[derive(Default, Debug)]
struct Key {
    pub value: u32,
}
unsafe impl Plain for Key {}

#[repr(C)]
#[derive(Default, Debug)]
struct Value {
    pub count: u64,
    pub processed_bytes: u64,
}
unsafe impl Plain for Value {}

fn main() -> Result<()> {
    let opts: Command = Command::from_args();

    let skel_builder: ConbiographSkelBuilder = ConbiographSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;

    if let Some(dir) = opts.cgroup_dir {
        use std::fs;
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(dir)?;
        let ino = meta.ino();

        open_skel.rodata().targ_cgid = ino;
    }

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("[!] Received Ctrl-C and summarizing");
        r.store(false, Ordering::SeqCst);
    })?;

    let mut points: Vec<(f32, f32)> = Vec::new();
    let mut countup = 0;

    println!(
        "Collecting events in {} ms... Ctrl-C to stop and show stat",
        opts.period
    );
    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(opts.period));
        let mut maps = skel.maps();
        let dist = maps.dist();
        let key = Key { value: 1 };
        let key_ = unsafe { plain::as_bytes(&key) };

        if let Some(value) = dist.lookup(key_, MapFlags::empty())? {
            let mut value_ = Value::default();
            plain::copy_from_bytes(&mut value_, &value).expect("invalid value bytes");

            let x = (countup * opts.period) as f32 / 1000f32;
            let y = if opts.show_count {
                value_.count as f32
            } else if opts.show_avg {
                if value_.count == 0 {
                    0.0f32
                } else {
                    value_.processed_bytes as f32 / value_.count as f32
                }
            } else {
                value_.processed_bytes as f32
            };
            points.push((x, y));
        }
        print!(".");
        let mut stdout = BufWriter::new(std::io::stdout());
        stdout.flush()?;
        countup += 1;
        if countup % 60 == 0 {
            print!("\n");
        }

        let value = Value {
            count: 0,
            processed_bytes: 0,
        };
        let value_ = unsafe { plain::as_bytes(&value) };

        dist.update(key_, value_, MapFlags::empty())?
    }
    println!("");

    let xmax = ((countup + 1) * opts.period) as f32 / 1000f32;
    Chart::new(200, 60, 0.0, xmax)
        .lineplot(&Shape::Steps(&points))
        .display();

    Ok(())
}
