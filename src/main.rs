use std::{path::PathBuf, fs::OpenOptions};

use structopt::StructOpt;
use wrsfs::create_dir;

mod wrsfs;
mod types;
mod helpers;

#[derive(Debug, StructOpt)]
#[structopt(name = "wrsfs")]
enum Args {
    Mkfs {
        name: PathBuf,
        size: u64
    },
    Mkdir {
        imgname: PathBuf,
        dir: String
    },
    Cp {
        imgname: PathBuf,
        filename: PathBuf,
        target_filename: String
    },
    Ls {
        imgname: PathBuf,
        #[structopt(default_value = "/")]
        dir: String
    },
    Info {
        imgname: PathBuf,
        #[structopt(short, long)]
        usage: bool,
        #[structopt(short, long)]
        pointers: bool,
    },
    Debug
}

fn main() {
    let args = Args::from_args();
    
    match args {
        Args::Mkfs { name, size } => mkfs(name, size),
        Args::Mkdir { imgname, dir } => mkdir(imgname, dir),
        Args::Cp { imgname, filename, target_filename } => cp(imgname, filename, target_filename),
        Args::Ls { imgname, dir } => ls(imgname, dir),
        Args::Info { imgname, usage, pointers } => info(imgname, usage, pointers),
        Args::Debug => debug(),
    }
}

fn mkfs(name: PathBuf, size: u64) {
    let cloned_name = name.clone();

    let path = cloned_name.as_path();
    let displayed = path.display();   

    match wrsfs::createfs(name, size) {
        Ok(()) => (),
        Err(why) => println!("Error creating filesystem: {}", why)
    }
    
    println!("{} created with size {}", displayed, size);
}

fn info(imgname: PathBuf, usage: bool, ptrs: bool) {
    match wrsfs::info(imgname, usage, ptrs) {
        Ok(()) => (),
        Err(why) => println!("Error getting info: {}", why)
    }
}

fn mkdir(imgname: PathBuf, dir: String) {
    let path = imgname.as_path();

    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(v) => v,
        Err(why) => { 
            println!("Couldn't open image {}: {}", path.to_str().unwrap(), why);
            return;
        }
    };

    match create_dir(&mut file, &dir) {
        Ok(_) => println!("Created dir {}", dir),
        Err(why) => println!("mkdir failed: {}", why)
    };
}

fn cp(imgname: PathBuf, filename: PathBuf, target_filename: String) {
    println!("{:?} {:?} {}", imgname, filename, target_filename);
}

fn ls(imgname: PathBuf, dir: String) {
    println!("{:?} {}", imgname, dir);
}

fn debug() {
    let bytes = [b'\\', 0, 0, 0];
    println!("{:?}", bytes);

    let str_from_bytes = helpers::get_string_from_array(&bytes); 

    println!("{}", str_from_bytes.len());

    println!("{}", str_from_bytes);
}

