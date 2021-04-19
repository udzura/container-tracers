use anyhow::Result;
use libbpf_rs::MapFlags;
use plain::Plain;

mod bpf;
use bpf::*;

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
            println!("key={:?}, value={:?}", key_, value_);
        }
    }

    Ok(())
}
