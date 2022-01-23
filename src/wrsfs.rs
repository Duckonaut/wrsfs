use std::{str, fs::{File, OpenOptions}, path::PathBuf, time::{UNIX_EPOCH, Duration, SystemTime}, os::unix::prelude::FileExt, io::{Read, BufRead}};
use chrono::{DateTime, Utc};
use serde::{Deserialize, de::DeserializeOwned};

use crate::{types::{self, Superblock, SMALLEST_IMAGE_SIZE, BLOCK_SIZE, DirectoryBlock, DirectoryFileEntry, INode, INODE_SIZE, FsBitmapBlock, BLOCK_BITMAP_SIZE_DESCRIBED}, helpers};
use crate::helpers::get_current_timestamp;


pub fn createfs(imgname: PathBuf, size: u64) -> Result<(), String> {
    if size < SMALLEST_IMAGE_SIZE { // 16 MB minimum disk, just to be sure
        return Err(format!("Image size {size} too small! Smallest size possible: {SMALLEST_IMAGE_SIZE}"));
    }

    let path = imgname.as_path();

    {
        let mut file = match File::create(path) {
            Ok(val) => val,
            Err(why) => return Err(why.to_string()),
        };

        match file.set_len(size) {
            Ok(()) => (),
            Err(why) => return Err(why.to_string()),
        };

        let superblock = types::Superblock::create(size);
    
        set_superblock(&mut file, superblock)?;
    }
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(v) => v,
        Err(why) => return Err(why.to_string())
    };

    match create_dir(&mut file, &String::from("/")) {
        Ok(_) => Ok(()),
        Err(why) => Err(why)
    }
}

pub fn info(imgname: PathBuf, usage: bool, ptrs: bool) -> Result<(), String> {
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

    if ptrs {
        println!("Block bitmap ptr: {}", superblock.block_bitmap_ptr);
        println!("INode bitmap ptr: {}", superblock.inode_bitmap_ptr);
        println!("INode blocks ptr: {}", superblock.inode_blocks_ptr);
        println!("Blocks ptr: {}", superblock.blocks_ptr);
    }

    if usage {
        println!("==== BLOCK USAGE ====");

        let bitmap_blocks = (superblock.inode_bitmap_ptr - superblock.block_bitmap_ptr) / BLOCK_SIZE as u64;

        let mut bitmap = [0u8; BLOCK_SIZE as usize];

        for i in 0..bitmap_blocks {
            match file.read_exact_at(&mut bitmap, superblock.block_bitmap_ptr + i * BLOCK_SIZE as u64) {
                Ok(()) => (),
                Err(why) => return Err(format!("Couldn't read block usage: {}", why))
            }

            let bitmap = match bincode::deserialize::<FsBitmapBlock>(&bitmap) {
                Ok(v) => v,
                Err(why) => return Err(format!("Couldn't deserialize bitmap: {}", why))
            };

            println!("{}", bitmap);
        }

        println!("==== INODE USAGE ====");

        let bitmap_blocks = (superblock.inode_blocks_ptr - superblock.inode_bitmap_ptr) / BLOCK_SIZE as u64;

        for i in 0..bitmap_blocks {
            match file.read_exact_at(&mut bitmap, superblock.inode_bitmap_ptr + i * BLOCK_SIZE as u64) {
                Ok(()) => (),
                Err(why) => return Err(format!("Couldn't read inode usage: {}", why))

            }

            let bitmap = match bincode::deserialize::<FsBitmapBlock>(&bitmap) {
                Ok(v) => v,
                Err(why) => return Err(format!("Couldn't deserialize bitmap: {}", why))
            };

            println!("{}", bitmap);
        }

    }

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
            let mut index = 0u64;

            while mask != 0 {
                if byte & mask == 0 {
                    count += 1;

                    if count == block_count {
                        free_blocks_ptr = superblock.blocks_ptr + (i * BLOCK_BITMAP_SIZE_DESCRIBED as u64) + ((byte_index as u64) * 8 + index + 1 - count as u64) * BLOCK_SIZE as u64;
                        break 'block_loop; 
                    }
                }
                else {
                    count = 0;
                }
                mask /= 2;
                index += 1;
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
        match file.read_exact_at(&mut block_bitmap_bytes, superblock.inode_bitmap_ptr + i * BLOCK_SIZE as u64) {
            Ok(()) => (),
            Err(why) => return Err(format!("Couldn't read inode bitmap: {}", why))
        }

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
    
    file.write_all_at(&mut bitmap_buffer, bitmap_block * BLOCK_SIZE as u64).expect("Couldn't write bitmap");

    Ok(())
}

fn set_inode_used(file: &mut File, inode_ptr: u64) -> Result<(), String> {
    let superblock = get_superblock(file)?;

    let block_index = (inode_ptr - superblock.inode_blocks_ptr) / BLOCK_SIZE as u64;
    let inode_index_in_block = (inode_ptr % BLOCK_SIZE as u64) / (BLOCK_SIZE / INODE_SIZE) as u64;
    let inode_bitmap_byte_address = superblock.inode_bitmap_ptr + block_index * BLOCK_SIZE as u64 + inode_index_in_block / 8;
    let mask = 0x80u8 >> (inode_index_in_block % 8);

    let mut inode_bitmap_byte: [u8; 1] = [0];

    match file.read_exact_at(&mut inode_bitmap_byte, inode_bitmap_byte_address) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't read bitmap: {}", why)),
    };

    inode_bitmap_byte[0] |= mask;


    match file.write_at(&inode_bitmap_byte, inode_bitmap_byte_address) {
        Ok(_) => (),
        Err(why) => return Err(format!("Couldn't write bitmap: {}", why)),
    };
    

    Ok(())
}


/// Returns a pointer to a directory block
pub fn create_dir(file: &mut File, dir: &String) -> Result<u64, String> {
    let free_blocks_for_dir = find_free_blocks(file, 1)?;
    
    let inode_ptr = find_free_inode(file)?;
    
    let superblock = get_superblock(file)?;
    
    if dir == "/" {
        let inode = INode {
            created_time: get_current_timestamp(),
            last_accessed: get_current_timestamp(),
            link_count: 1,
            subtype_info: types::INodeSubtype::Directory {
                item_count: 1,
                inode_table_block: ((free_blocks_for_dir - superblock.blocks_ptr) / BLOCK_SIZE as u64) as u32,
            },
        };

        let mut dir_block = DirectoryBlock {
            file_entries: [DirectoryFileEntry {
                filename: [0u8; 56],
                file_inode_ptr: 0,
            }; 64]
        };

        let mut filename_bytes = [0u8; 56];
        filename_bytes[0] = b'.';
       
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

        update_superblock(file)?;
    }
    else {
        let inode = INode {
            created_time: get_current_timestamp(),
            last_accessed: get_current_timestamp(),
            link_count: 2, // self and parent
            subtype_info: types::INodeSubtype::Directory {
                item_count: 2,
                inode_table_block: ((free_blocks_for_dir - superblock.blocks_ptr) / BLOCK_SIZE as u64) as u32,
            },
        };

        let mut dir_block = DirectoryBlock {
            file_entries: [DirectoryFileEntry {
                filename: [0u8; 56],
                file_inode_ptr: 0,
            }; 64]
        };

        let path_parts = dir.split("/").collect::<Vec<&str>>();
        let parent_path = path_parts[0..(path_parts.len()-1)].join("/");

        dbg!(&parent_path);

        let parent_folder = if parent_path == "" {
            superblock.inode_blocks_ptr
        }
        else {
            match find_folder_inode(file, &parent_path)? {
                Some(v) => v,
                None => create_dir(file, &parent_path)?
            }
        };

        dbg!(&parent_folder);

        let dir_name = match path_parts.last() {
            Some(v) => v.to_owned(),
            None => return Err(format!("The path {} is invalid", dir))
        };

        let filename_vec: Vec<u8> = String::from(dir_name).into_bytes();

        let mut filename_bytes = [0u8; 56];
        
        for i in 0..(std::cmp::min(filename_vec.len(), 56)) {
            filename_bytes[i] = filename_vec[i];
        }

        let mut dot_bytes = [0u8; 56];
        dot_bytes[0] = b'.';

        let mut dot_dot_bytes = [0u8; 56];
        dot_dot_bytes[0] = b'.';
        dot_dot_bytes[1] = b'.';
        
        dir_block.file_entries[0] = DirectoryFileEntry {
            filename: dot_bytes,
            file_inode_ptr: inode_ptr,
        };

        dir_block.file_entries[1] = DirectoryFileEntry {
            filename: dot_dot_bytes,
            file_inode_ptr: inode_ptr,
        };

        let mut parent_folder_inode = get_inode(file, parent_folder)?;
        parent_folder_inode.link_count += 1;
        parent_folder_inode.last_accessed = helpers::get_current_timestamp();

        match parent_folder_inode.subtype_info {
            types::INodeSubtype::File { .. } => return Err(format!("{} is a file!", parent_path)),
            types::INodeSubtype::Directory { mut item_count, inode_table_block } => {
                item_count += 1;
                let file_entry_address = superblock.blocks_ptr + inode_table_block as u64 * BLOCK_SIZE as u64;

                dbg!(&file_entry_address);


                let mut parent_file_entries = get_file_struct::<DirectoryBlock, 0x1000>(file, file_entry_address)?;
                parent_file_entries.file_entries[item_count as usize] = DirectoryFileEntry {
                    filename: filename_bytes,
                    file_inode_ptr: free_blocks_for_dir
                };

                match file.write_all_at(&(match bincode::serialize(&parent_file_entries) {
                        Ok(b) => b,
                        Err(why) => return Err(format!("Couldn't serialize dir block: {}", why))
                    }), file_entry_address) {
                    Ok(()) => (),
                    Err(why) => return Err(format!("Couldn't write dir block: {}", why)),
                }
            }
        };

        match file.write_all_at(&(match bincode::serialize(&parent_folder_inode) {
                Ok(b) => b,
                Err(why) => return Err(format!("Couldn't serialize parent inode: {}", why))
            }), parent_folder) {
            Ok(()) => (),
            Err(why) => return Err(format!("Couldn't write parent inode: {}", why)),
        }


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

        update_superblock(file)?;

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

fn find_folder_inode(file: &mut File, path: &String) -> Result<Option<u64>, String> {
    let path_split = path.split("/");
   
    let superblock = get_superblock(file)?;

    let base_dir_inode = get_inode(file, superblock.inode_blocks_ptr)?;


    let mut current_inode = base_dir_inode;
    let mut current_inode_address = superblock.inode_blocks_ptr;

    for path_part in path_split {
        match current_inode.subtype_info {
            types::INodeSubtype::File { .. } => return Err(format!("Expected directory inode, found file inode.")),
            types::INodeSubtype::Directory { item_count, inode_table_block } => {
                let dir_block = get_file_struct::<DirectoryBlock, 0x1000>(file, superblock.blocks_ptr + inode_table_block as u64 * BLOCK_SIZE as u64)?;
                
                let mut dir_exists = false;

                for i in 0..item_count {
                    let dir_file = dir_block.file_entries[i as usize];

                    let filename = helpers::get_string_from_array(&dir_file.filename); 

                    if filename == path_part {
                        current_inode = get_inode(file, dir_file.file_inode_ptr)?;
                        current_inode_address = dir_file.file_inode_ptr;
                        dir_exists = true;
                        break;
                    }
                }

                if !dir_exists {
                    return Ok(None);
                }
            }
        }
    }

    Ok(Some(current_inode_address))
}

fn get_inode(file: &mut File, inode_ptr: u64) -> Result<INode, String> {
   get_file_struct::<INode, 0x40>(file, inode_ptr) 
}

/// Util function. Garbage in, garbage out, so yeah.
fn get_file_struct<'de, T: Sized + DeserializeOwned, const BYTE_COUNT: usize>(file: &mut File, struct_ptr: u64) -> Result<T, String> {
    let mut struct_buf = [0u8; BYTE_COUNT];

    match file.read_exact_at(&mut struct_buf, struct_ptr) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't get struct at {}: {}", struct_ptr, why))
    };

    match bincode::deserialize::<T>(&struct_buf) {
        Ok(v) => Ok(v),
        Err(why) => Err(format!("Couldn't deserialize struct at {}: {}", struct_ptr, why))
    }
}

fn update_superblock_access(file: &mut File) -> Result<(), String> {
    let current_time = get_current_timestamp(); 

    let mut superblock = get_superblock(file)?;

    superblock.last_accessed_time = current_time;

    set_superblock(file, superblock)
}

fn update_superblock(file: &mut File) -> Result<(), String> {
    let mut superblock = get_superblock(file)?;
    
    update_superblock_access(file)?;

    let bitmap_block_count = (superblock.inode_bitmap_ptr - superblock.block_bitmap_ptr) / BLOCK_SIZE as u64;

    let mut block_bitmap_bytes = [0u8; BLOCK_SIZE as usize];

    let mut count = 0u32;
    
    for i in 0..bitmap_block_count {
        match file.read_exact_at(&mut block_bitmap_bytes, superblock.block_bitmap_ptr + i * BLOCK_SIZE as u64) {
            Ok(()) => (),
            Err(why) => return Err(format!("Error updating superblock block usage: {}", why))
        }
        
        for byte in block_bitmap_bytes {
            let mut mask = 0x80u8;

            while mask != 0 {
                if byte & mask == 1 {
                    count += 1;
                
                }
                mask /= 2;
            }
        }
    }

    superblock.block_free = superblock.block_count - (superblock.blocks_ptr / BLOCK_SIZE as u64) as u32 - count as u32;

    let bitmap_block_count = (superblock.inode_blocks_ptr - superblock.inode_bitmap_ptr) / BLOCK_SIZE as u64;

    count = 0;

    for i in 0..bitmap_block_count {
        match file.read_exact_at(&mut block_bitmap_bytes, superblock.inode_bitmap_ptr + i * BLOCK_SIZE as u64) {
            Ok(()) => (),
            Err(why) => return Err(format!("Error updating superblock inodes used: {}", why))
        }

        
        for byte in block_bitmap_bytes {
            let mut mask = 0x80u8;

            while mask != 0 {
                if byte & mask != 0 {
                    count += 1;
                }
                mask /= 2;
            }
        }
    }

    superblock.inode_free = superblock.inode_count - count;
    
    set_superblock(file, superblock)
}
