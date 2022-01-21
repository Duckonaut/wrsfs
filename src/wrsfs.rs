use std::{fs::{File, OpenOptions}, path::PathBuf, time::{UNIX_EPOCH, Duration, SystemTime}, os::unix::prelude::FileExt, io::Read};
use chrono::{DateTime, Utc};

use crate::types::{self, Superblock, SMALLEST_IMAGE_SIZE, BLOCK_SIZE, DirectoryBlock, DirectoryFileEntry, INode, INODE_SIZE};
use crate::helpers::get_current_timestamp;


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

/// Returns a pointer to the first section of `block_count` blocks
pub fn find_free_blocks(file: &mut File, block_count: u32) -> Result<u64, String> {
    let superblock = get_superblock(file)?;

    let mut block_bitmap_bytes = [0u8; BLOCK_SIZE as usize];

    let bitmap_block_count = (superblock.inode_bitmap_ptr - superblock.block_bitmap_ptr) / BLOCK_SIZE as u64;

    let mut free_blocks_ptr: u64 = 0;

    'block_loop: for i in 0..bitmap_block_count {
        file.read_exact_at(&mut block_bitmap_bytes, superblock.block_bitmap_ptr + i * BLOCK_SIZE as u64);

        let mut count = 0u32;
        
        for (byte_index, byte) in block_bitmap_bytes.iter().enumerate() {
            let mut mask = 0x80u8;

            while mask != 0 {
                if byte & mask == 0 {
                    count += 1;

                    if count == block_count {
                        free_blocks_ptr = superblock.blocks_ptr + ((i * BLOCK_SIZE as u64 + byte_index as u64 - block_count as u64) * 8) * BLOCK_SIZE as u64;
                        break 'block_loop; 
                    }
                }
                else {
                    count = 0;
                }
                mask /= 2;
            }
        }
    }
    
    if free_blocks_ptr == 0 {
        Err(format!("Couldn't find {} free blocks", block_count))
    }
    else {
        Ok(free_blocks_ptr)
    }
}

/// Returns a pointer to the free INode section
pub fn find_free_inode(file: &mut File) -> Result<u64, String> {
    let superblock = get_superblock(file)?;

    let mut block_bitmap_bytes = [0u8; BLOCK_SIZE as usize];

    let bitmap_block_count = (superblock.inode_blocks_ptr - superblock.inode_bitmap_ptr) / BLOCK_SIZE as u64;

    let mut free_inode_ptr: u64 = 0;

    'block_loop: for i in 0..bitmap_block_count {
        file.read_exact_at(&mut block_bitmap_bytes, superblock.inode_bitmap_ptr + i * BLOCK_SIZE as u64);

        let ptr = 0usize;
        for byte in block_bitmap_bytes {
            let mut mask = 0x80u8;

            while mask != 0 {
                if byte & mask == 0 {
                    free_inode_ptr = superblock.inode_blocks_ptr + ((i * BLOCK_SIZE as u64) * 8 + ptr as u64) * INODE_SIZE as u64;
                    break 'block_loop; 
                }

                mask /= 2;
            }
        }
    }

    if free_inode_ptr == 0 {
        Err(String::from("Couldn't find free inode"))
    }
    else {
        Ok(free_inode_ptr)
    }
}

fn set_blocks_used(file: &mut File, block_ptr: u64, block_count: u64) -> Result<(), String> {
    let superblock = get_superblock(file)?;

    let block_index = (block_ptr - superblock.blocks_ptr) / BLOCK_SIZE as u64;

    let bitmap_start_byte = superblock.block_bitmap_ptr + block_index / 8;

    let start_offset_in_byte = block_index % 8;

    let mut mask = 0x80 >> start_offset_in_byte;

    let mut bitmap_buffer = [0u8; BLOCK_SIZE as usize];

    let current_block = bitmap_start_byte / BLOCK_SIZE as u64;

    match file.read_exact_at(&mut bitmap_buffer, current_block * BLOCK_SIZE as u64) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't read bitmap: {}", why)),
    };

    let mut blocks_set = 0;
    let mut bitmap_block = current_block;
    let mut bitmap_ptr = bitmap_start_byte % BLOCK_SIZE as u64;
    
    while blocks_set != block_count {
        let mut byte: u8 = match bitmap_buffer[bitmap_ptr as usize].try_into() {
            Ok(v) => v,
            Err(why) => return Err(format!("Failed to get byte to set: {}", why)),
        };

        while mask != 0 {
            byte |= mask;
            blocks_set += 1;

            if blocks_set == block_count {
                break;
            }

            mask /= 2;
        }

        bitmap_buffer[bitmap_ptr as usize] = byte;

        bitmap_ptr += 1;
        mask = 0x80;

        if bitmap_ptr >= BLOCK_SIZE as u64 {
            file.write_all_at(&mut bitmap_buffer, bitmap_block * BLOCK_SIZE as u64).expect("Couldn't write bitmap");

            bitmap_block += 1;

            file.read_exact_at(&mut bitmap_buffer, bitmap_block * BLOCK_SIZE as u64).expect("Couldn't read bitmap");

            bitmap_ptr = 0;
        }
            
    }

    Ok(())
}

fn set_inode_used(file: &mut File, inode_ptr: u64) -> Result<(), String> {
    let superblock = get_superblock(file)?;

    let block_index = (inode_ptr - superblock.inode_blocks_ptr) / BLOCK_SIZE as u64;
    let inode_index_in_block = (inode_ptr % BLOCK_SIZE as u64) / (INODE_SIZE / BLOCK_SIZE) as u64;
    let inode_bitmap_byte_address = superblock.inode_bitmap_ptr + block_index * BLOCK_SIZE as u64 + inode_index_in_block / 8;
    let mask = 0x80u8 >> inode_index_in_block % 8;

    let mut inode_bitmap_byte: [u8; 1] = [0];
    
    match file.read_exact_at(&mut inode_bitmap_byte, inode_bitmap_byte_address) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't read bitmap: {}", why)),
    };

    inode_bitmap_byte[0] |= mask;

    match file.write_all_at(&mut inode_bitmap_byte, inode_bitmap_byte_address) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't write bitmap: {}", why)),
    };
    

    Ok(())
}


/// Returns a pointer to a directory block
pub fn create_dir(file: &mut File, dir: String) -> Result<u64, String> {
    let free_blocks_for_dir = find_free_blocks(file, 1)?; 

    let inode_ptr = find_free_inode(file)?;

    if dir == "/" {
        let inode = INode {
            created_time: get_current_timestamp(),
            last_accessed: get_current_timestamp(),
            link_count: 1,
            subtype_info: types::INodeSubtype::Directory {
                item_count: 1,
                inode_table_block_ptr: free_blocks_for_dir,
            },
        };

        let mut dir_block = DirectoryBlock {
            file_entries: [DirectoryFileEntry {
                filename: [0u8; 56],
                file_inode_ptr: 0,
            }; 64]
        };

        let filename_bytes: [u8; 56] = match ".".as_bytes().try_into() {
            Ok(value) => value,
            Err(why) => return Err(format!("Couldn't create dir: {}", why)),
        };

        dir_block.file_entries[0] = DirectoryFileEntry {
            filename: filename_bytes,
            file_inode_ptr: inode_ptr,
        }; 

        match file.write_all_at(&(match bincode::serialize(&inode) {
                Ok(b) => b,
                Err(why) => return Err(format!("Couldn't serialize inode: {}", why))
            }), inode_ptr) {
            Ok(()) => (),
            Err(why) => return Err(format!("Couldn't write inode: {}", why)),
        }

        match file.write_all_at(&(match bincode::serialize(&dir_block) {
                Ok(b) => b,
                Err(why) => return Err(format!("Couldn't serialize directory block: {}", why))
            }), free_blocks_for_dir) {
            Ok(()) => (),
            Err(why) => return Err(format!("Couldn't write directory block: {}", why)),
        }

        set_inode_used(file, inode_ptr)?;
        set_blocks_used(file, free_blocks_for_dir, 1)?;
    }

    Ok(free_blocks_for_dir)
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
