use anyhow::Result;
use libbpf_rs::MapFlags;
use plain::Plain;
use structopt::StructOpt;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{mem, slice};

mod bpf;
use bpf::*;

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
    let skel_builder: ConbiographSkelBuilder = ConbiographSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("[!] Received Ctrl-C and summarizing");
        r.store(false, Ordering::SeqCst);
    })?;

    println!("Collecting events... Ctrl-C to stop and show stat");
    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_secs(1));
        let mut maps = skel.maps();
        let dist = maps.dist();
        let key = Key { value: 1 };
        let key_ = unsafe { plain::as_bytes(&key) };

        if let Some(value) = dist.lookup(key_, MapFlags::empty())? {
            let mut value_ = Value::default();
            plain::copy_from_bytes(&mut value_, &value).expect("invalid value bytes");

            println!("Got: {:?}", value_);
        }

        let value = Value {
            count: 0,
            processed_bytes: 0,
        };
        let value_ = unsafe { plain::as_bytes(&value) };

        dist.update(key_, value_, MapFlags::empty())?
    }
    println!("");

    Ok(())
}
