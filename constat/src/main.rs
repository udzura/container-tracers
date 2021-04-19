use anyhow::Result;
use libbpf_rs::MapFlags;
use plain::Plain;
#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;

mod bpf;
use bpf::*;

pub const AUSYSCALL_RESULT: &'static str = include_str!("ausyscall.txt");

lazy_static! {
    pub static ref SYSCALL2NAME: HashMap<u64, &'static str> = {
        let mut m = HashMap::new();
        for line in AUSYSCALL_RESULT.split('\n').into_iter() {
            let row = line.split('\t').collect::<Vec<&str>>();
            if let Ok(key) = row[0].parse::<u64>() {
                let value = row[1];
                m.insert(key, value);
            }
        }
        m
    };
}

#[repr(C)]
#[derive(Default, Debug)]
struct Key {
    pub tid: u32,
    pub syscall_nr: u64,
}
unsafe impl Plain for Key {}

#[repr(C)]
#[derive(Default, Debug)]
struct Value {
    pub count: u64,
    pub elapsed_ns: u64,
    pub enter_ns: u64,
}
unsafe impl Plain for Value {}

fn main() -> Result<()> {
    let mut skel_builder: ConstatSkelBuilder = ConstatSkelBuilder::default();
    let mut open_skel: OpenConstatSkel = skel_builder.open()?;
    // open_skel.rodata()...

    let mut skel: ConstatSkel = open_skel.load()?;
    skel.attach()?;

    std::thread::sleep(std::time::Duration::from_secs(1));

    let mut maps = skel.maps();
    let mut dist = maps.dist();
    for key in dist.keys() {
        if let Some(value) = dist.lookup(&key, MapFlags::empty())? {
            let mut key_ = Key::default();
            plain::copy_from_bytes(&mut key_, &key).expect("invalid key bytes");
            let mut value_ = Value::default();
            plain::copy_from_bytes(&mut value_, &value).expect("invalid value bytes");
            println!(
                "tid={}, syscall={}, value={:?}",
                key_.tid, SYSCALL2NAME[&key_.syscall_nr], value_
            );
        }
    }

    Ok(())
}
