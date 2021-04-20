use anyhow::Result;
use libbpf_rs::MapFlags;
use plain::Plain;
use structopt::StructOpt;

#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::{mem, slice};

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

#[derive(Debug, StructOpt)]
struct Command {
    /// Target cgroup directory to track
    #[structopt(short = "c", value_name = "CGROUP_DIR")]
    cgroup_dir: Option<String>,
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

#[repr(C)]
#[derive(Default, Debug)]
struct CgidFileHandle {
    pub handle_bytes: u32,
    pub handle_type: i32,
    pub cgid: u64,
}
unsafe impl Plain for CgidFileHandle {}

fn main() -> Result<()> {
    let opts: Command = Command::from_args();

    let mut skel_builder: ConstatSkelBuilder = ConstatSkelBuilder::default();
    let mut open_skel: OpenConstatSkel = skel_builder.open()?;

    if let Some(dir) = opts.cgroup_dir {
        let mut handle = nc::types::file_handle_t::default();
        handle.handle_bytes = 8;
        let mut _mount_id = 0i32;

        nc::name_to_handle_at(nc::types::AT_FDCWD, &dir, &mut handle, &mut _mount_id, 0)
            .expect("Cannot find cgid");

        let mut dist = CgidFileHandle::default();
        unsafe {
            let bptr = &handle as *const nc::types::file_handle_t as *const u8;
            let bsize = mem::size_of_val(&dist);
            let data = slice::from_raw_parts(bptr, bsize);

            plain::copy_from_bytes(&mut dist, &data).expect("Invalid file handle");
        }
        open_skel.rodata().targ_cgid = dist.cgid;
    }

    let mut skel: ConstatSkel = open_skel.load()?;
    skel.attach()?;

    std::thread::sleep(std::time::Duration::from_secs(10));

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
