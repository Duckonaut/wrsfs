use std::{fs::{File, OpenOptions}, path::PathBuf, time::{UNIX_EPOCH, Duration, SystemTime}, os::unix::prelude::FileExt};
use chrono::{DateTime, Utc};

use crate::types::{self, Superblock, SMALLEST_IMAGE_SIZE};

pub fn createfs(imgname: PathBuf, size: u64) -> Result<(), String> {
    if size < SMALLEST_IMAGE_SIZE { // 16 MB minimum disk, just to be sure
        return Err(format!("Image size {size} too small! Smallest size possible: {SMALLEST_IMAGE_SIZE}"));
    }

    let path = imgname.as_path();

    let mut file = match File::create(path) {
        Ok(val) => val,
        Err(why) => return Err(why.to_string()),
    };

    match file.set_len(size) {
        Ok(()) => (),
        Err(why) => return Err(why.to_string()),
    }; 

    let superblock = types::Superblock::create(size);
    
    set_superblock(&mut file, superblock)
}

pub fn info(imgname: PathBuf) -> Result<(), String> {
    let mut file = match OpenOptions::new().read(true).write(true).open(&imgname) {
        Ok(file) => file,
        Err(why) => return Err(format!("Couldn't get info for {:?}: {}", imgname, why)),
    };

    let superblock = get_superblock(&mut file)?;
    
    println!("Block size: {}", superblock.block_size);
    println!("Block count: {}", superblock.block_count);
    println!("Blocks free: {} ({:.2}%)", superblock.block_free, (superblock.block_free as f64 / superblock.block_count as f64) * 100.0);
    println!("Time created: {}", DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(superblock.created_time))
        .format("%Y-%m-%d %H:%M:%S.%f")
        .to_string());

    println!("Time last accessed: {}", DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(superblock.last_accessed_time))
        .format("%Y-%m-%d %H:%M:%S.%f")
        .to_string());

    println!("INode size: {}", superblock.inode_size);
    println!("INode count: {}", superblock.inode_count);
    println!("INode blocks: {}", superblock.inode_block_count);
    println!("INodes unused: {}", superblock.inode_free);

    update_superblock_access(&mut file)?;

    Ok(())
}

fn get_superblock(file: &mut File) -> Result<Superblock, String> {
    let mut superblock_encoded = [0u8; std::mem::size_of::<types::Superblock>()];
    match file.read_exact_at(&mut superblock_encoded, 0) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't read superblock: {}", why)),
    }
    
    match bincode::deserialize::<types::Superblock>(&superblock_encoded) {
        Ok(value) => Ok(value),
        Err(why) => return Err(format!("Couldn't deserialize superblock. Image corrupted?: {}", why))
    }
}

fn set_superblock(file: &mut File, superblock: Superblock) -> Result<(), String> {
    let superblock_serialized = match bincode::serialize(&superblock) {
        Ok(v) => v,
        Err(why) => return Err(why.to_string()),
    };

    match file.write_all_at(&superblock_serialized, 0) {
        Ok(()) => Ok(()),
        Err(why) => Err(why.to_string()),
    }
}

fn update_superblock_access(file: &mut File) -> Result<(), String> {
    let current_time = SystemTime::now();
    let current_time = current_time.duration_since(UNIX_EPOCH).expect("Datetime error").as_secs();


    let mut superblock = get_superblock(file)?;

    superblock.last_accessed_time = current_time;

    set_superblock(file, superblock)
}
