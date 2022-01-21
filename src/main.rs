use std::path::PathBuf;

use structopt::StructOpt;

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
        imgname: PathBuf
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
        Args::Info { imgname } => info(imgname),
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

fn info(imgname: PathBuf) {
    match wrsfs::info(imgname) {
        Ok(()) => (),
        Err(why) => println!("Error getting info: {}", why)
    }
}

fn mkdir(imgname: PathBuf, dir: String) { 
    println!("{:?} {}", imgname, dir);
}

fn cp(imgname: PathBuf, filename: PathBuf, target_filename: String) {
    println!("{:?} {:?} {}", imgname, filename, target_filename);
}

fn ls(imgname: PathBuf, dir: String) {
    println!("{:?} {}", imgname, dir);
}

fn debug() {
    println!("{}", std::mem::size_of::<types::Superblock>());

    println!("{}", std::mem::size_of::<types::INode>());

    println!("{}", std::mem::size_of::<types::INodeBlock>());

    println!("{}", std::mem::size_of::<types::FsBitmapBlock>());

    println!("{}", std::mem::size_of::<types::FsBitmap>());

    println!("{}", std::mem::size_of::<types::DirectoryBlock>());
}

