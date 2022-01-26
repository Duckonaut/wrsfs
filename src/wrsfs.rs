use std::{str, fs::{File, OpenOptions}, path::PathBuf, time::{UNIX_EPOCH, Duration}, os::unix::prelude::FileExt, io::{Read, Write}};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;

use crate::{types::{self, Superblock, SMALLEST_IMAGE_SIZE, BLOCK_SIZE, DirectoryBlock, DirectoryFileEntry, INode, INodeSubtype, INODE_SIZE, FsBitmapBlock, BLOCK_BITMAP_SIZE_DESCRIBED, FileFirstIndirectBlock, FileSecondIndirectBlock}, helpers};
use crate::helpers::get_current_timestamp;

/// Creates a WRSFS virtual disk as a file at <imgname> with size <size> in bytes
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

/// Shows info about a virtual disk at <imgname> with extra info flags <usage> and <ptrs>
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

/// Returns a pointer to a directory block
pub fn create_dir(file: &mut File, dir: &String) -> Result<u64, String> {
    let free_blocks_for_dir = find_free_blocks(file, 1)?;
    
    dbg!(&free_blocks_for_dir);

    set_blocks_used(file, free_blocks_for_dir, 1, true)?;
    
    let inode_ptr = find_free_inode(file)?;

    set_inode_used(file, inode_ptr, true)?;
    
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

        dbg!(&inode);

        let mut dir_block = DirectoryBlock {
            file_entries: [DirectoryFileEntry {
                filename: [0u8; 56],
                file_inode_ptr: 0,
            }; 64]
        };

        let path_parts = dir.split("/").collect::<Vec<&str>>();
        let parent_path = path_parts[0..(path_parts.len()-1)].join("/");

        let parent_folder = if parent_path == "" {
            superblock.inode_blocks_ptr
        }
        else {
            match find_folder_inode(file, &parent_path)? {
                Some(v) => v,
                None => create_dir(file, &parent_path)?
            }
        };
        

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
            file_inode_ptr: parent_folder,
        };

        dbg!(&parent_folder);

        let mut parent_folder_inode = get_inode(file, parent_folder)?;
        
        dbg!(&parent_folder_inode);

        parent_folder_inode.last_accessed = helpers::get_current_timestamp();

        match parent_folder_inode.subtype_info {
            types::INodeSubtype::File { .. } => return Err(format!("{} is a file!", parent_path)),
            types::INodeSubtype::Directory { ref mut item_count, inode_table_block } => {
                let file_entry_address = superblock.blocks_ptr + inode_table_block as u64 * BLOCK_SIZE as u64;

                let mut parent_file_entries = get_file_struct::<DirectoryBlock, 0x1000>(file, file_entry_address)?;

                for entry in parent_file_entries.file_entries {
                    if entry.filename == filename_bytes {
                        return Err(format!("Directory/file {} already exists in {}", dir_name, parent_path));
                    }
                }

                parent_file_entries.file_entries[*item_count as usize] = DirectoryFileEntry {
                    filename: filename_bytes,
                    file_inode_ptr: inode_ptr
                };

                *item_count += 1;
                
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

        update_superblock(file)?;

    }
    Ok(inode_ptr)
}

/// Copies file <file> to file at path <dir> in <img_file>
pub fn copy_file(img_file: &mut File, file: &mut File, dir: &String) -> Result<(), String> {
    let superblock = get_superblock(img_file)?;

    let inode_ptr = find_free_inode(img_file)?;
   

    let dir = String::from(dir.trim_matches('/'));
    let dir_split = dir.split('/').collect::<Vec<&str>>();

    let filename = match dir_split.last() {
        Some(v) => v.to_owned(),
        None => return Err(format!("Cannot create file with empty name \"{}\".", dir))
    };

    let parent_path = dir_split[0..(dir_split.len()-1)].join("/");

    let parent_inode_address = if parent_path == "" {
        superblock.inode_blocks_ptr
    }
    else {
        match find_folder_inode(img_file, &parent_path)? {
            Some(v) => v,
            None => return Err(format!("Directory {} does not exist.", parent_path))
        }
    };

    let filename_vec: Vec<u8> = String::from(filename).into_bytes();

    let mut filename_bytes = [0u8; 56];
        
    for i in 0..(std::cmp::min(filename_vec.len(), 56)) {
        filename_bytes[i] = filename_vec[i];
    }

    let mut dir_inode = get_inode(img_file, parent_inode_address)?;
    
    dir_inode.last_accessed = helpers::get_current_timestamp();
    
    match dir_inode.subtype_info {
        INodeSubtype::File { .. } => return Err(format!("{} is a file, not a directory.", &parent_path)),
        INodeSubtype::Directory { ref mut item_count, inode_table_block } => {
            let file_entry_address = superblock.blocks_ptr + inode_table_block as u64 * BLOCK_SIZE as u64;

            let mut parent_file_entries = get_file_struct::<DirectoryBlock, 0x1000>(img_file, file_entry_address)?;
            
            for entry in parent_file_entries.file_entries {
                if entry.filename == filename_bytes {
                    return Err(format!("Directory/file {} already exists in {}", &filename, parent_path));
                }
            }

            parent_file_entries.file_entries[*item_count as usize] = DirectoryFileEntry {
                filename: filename_bytes,
                file_inode_ptr: inode_ptr
            };

            *item_count += 1;
                
            match img_file.write_all_at(&(match bincode::serialize(&parent_file_entries) {
                    Ok(b) => b,
                    Err(why) => return Err(format!("Couldn't serialize dir block: {}", why))
                }), file_entry_address) {
                Ok(()) => (),
                Err(why) => return Err(format!("Couldn't write dir block: {}", why)),
            }
        },
    }

    match img_file.write_all_at(&(match bincode::serialize(&dir_inode) {
            Ok(b) => b,
            Err(why) => return Err(format!("Couldn't serialize directory inode: {}", why))
        }), parent_inode_address) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't write directory inode: {}", why)),
    }


    let file_metadata = match file.metadata() {
        Ok(m) => m,
        Err(why) => return Err(format!("Failed to get file metadata: {}", why))
    };

    let filesize = file_metadata.len();

    let file_blocks = ((filesize as u64 + BLOCK_SIZE as u64 - 1u64) / BLOCK_SIZE as u64) as u32;
    
    let mut block_ptrs = [0u32; 8];

    let allocated = find_free_blocks(img_file, file_blocks)?;
    
    set_blocks_used(img_file, allocated, file_blocks as u64, true)?;

    let starting_block = ((allocated - superblock.blocks_ptr) / BLOCK_SIZE as u64) as u32;

    for i in 0..std::cmp::min(file_blocks, 8) {
        block_ptrs[i as usize] = starting_block + i as u32;
    }

    let mut first_layer_indirect_ptrs = FileFirstIndirectBlock {
        more_indirect_blocks: [0u32; 0x400]
    };
    
    let extra_block_count = if filesize < 0x8000 {
        0
    }
    else {
        (filesize - BLOCK_SIZE as u64 * 7 - 1) / 0x1000
    };

    let mut blocks_left = extra_block_count;

    let second_layer_blocks = (extra_block_count + 0x3FF) / 0x400;

    let indirect_first_ptr = if extra_block_count > 0 {
        let first_layer_ptr = find_free_blocks(img_file, 1)?;
        set_blocks_used(img_file, first_layer_ptr, 1, true)?;

        for i in 0..second_layer_blocks {
            let second_layer_indirect_ptr = find_free_blocks(img_file, 1)?;
            
            let mut second_layer_indirect_block = FileSecondIndirectBlock {
                blocks: [0u32; 0x400]
            };

            for j in 0..(std::cmp::min(blocks_left, 0x400)) {
                second_layer_indirect_block.blocks[j as usize] = (starting_block as u64 + 8 + i * 0x400 + j) as u32;
                blocks_left -= 1;
            }

            first_layer_indirect_ptrs.more_indirect_blocks[i as usize] = ((second_layer_indirect_ptr - superblock.blocks_ptr) / BLOCK_SIZE as u64) as u32;

            match img_file.write_all_at(match &(bincode::serialize(&second_layer_indirect_block)) {
                    Ok(v) => v,
                    Err(why) => return Err(format!("Failed to serialize ptr block: {}", why))
                }, second_layer_indirect_ptr) {
                Ok(_) => set_blocks_used(img_file, second_layer_indirect_ptr, 1, true)?,
                Err(why) => return Err(format!("Failed to write ptr block: {}", why))
            }
        }

        match img_file.write_all_at(match &(bincode::serialize(&first_layer_indirect_ptrs)) {
                Ok(v) => v,
                Err(why) => return Err(format!("Failed to serialize ptr block: {}", why))
            }, first_layer_ptr) {
            Ok(_) => (),
            Err(why) => return Err(format!("Failed to write ptr block: {}", why))
        }

        first_layer_ptr
    }
    else {
        0
    };

    let indirect_inode_block = if indirect_first_ptr > 0 {
        ((indirect_first_ptr - superblock.blocks_ptr) / BLOCK_SIZE as u64) as u32
    }
    else {
        0
    };

    
    let file_inode = INode {
        created_time: helpers::get_current_timestamp(),
        last_accessed: helpers::get_current_timestamp(),
        link_count: 1,
        subtype_info: INodeSubtype::File {
            size: filesize as u32,
            direct_block_ptrs: block_ptrs,
            indirect_ptr: indirect_inode_block
        },
    };

    let mut block_to_write = 0;

    let mut bytes_left = filesize;

    while bytes_left > 0 {
        let mut buf = vec![0u8; std::cmp::min(bytes_left as usize, 0x1000)];

        match file.read_exact(&mut buf) {
            Ok(_) => (),
            Err(why) => return Err(format!("Failed to read file: {}", why)),
        }

        let dest_address = allocated + block_to_write * BLOCK_SIZE as u64;

        block_to_write += 1;

        match img_file.write_all_at(&mut buf, dest_address) {
            Ok(_) => (),
            Err(why) => return Err(format!("Failed to copy file: {}", why))
        }

        bytes_left -= std::cmp::min(bytes_left, 0x1000);
    }

    match img_file.write_all_at(match &(bincode::serialize(&file_inode)) {
                Ok(v) => v,
                Err(why) => return Err(format!("Failed to serialize inode: {}", why))
            }, inode_ptr) {
        Ok(_) => set_inode_used(img_file, inode_ptr, true)?,
        Err(why) => return Err(format!("Failed to write inode: {}", why))
    }

    update_superblock(img_file)?;

    Ok(())
}

/// Copies file <dir> from virtual disk <img_file> to file on disk at <file_to_write>
pub fn get_file(img_file: &mut File, file_to_write: &PathBuf, dir: &String) -> Result<(), String> {
    let superblock = get_superblock(img_file)?;
   
    let dir = String::from(dir.trim_matches('/'));
    let dir_split = dir.split('/').collect::<Vec<&str>>();

    let filename = match dir_split.last() {
        Some(v) => v.to_owned(),
        None => return Err(format!("Cannot find file with empty name \"{}\".", dir))
    };

    let parent_path = dir_split[0..(dir_split.len()-1)].join("/");

    let parent_inode_address = if parent_path == "" {
        superblock.inode_blocks_ptr
    }
    else {
        match find_folder_inode(img_file, &parent_path)? {
            Some(v) => v,
            None => return Err(format!("Directory {} does not exist.", parent_path))
        }
    };

    let mut dir_inode = get_inode(img_file, parent_inode_address)?;
    
    dir_inode.last_accessed = helpers::get_current_timestamp();
    
    let mut file_inode_address = 0u64;

    match dir_inode.subtype_info {
        INodeSubtype::File { .. } => return Err(format!("{} is a file, not a directory.", &parent_path)),
        INodeSubtype::Directory { item_count, inode_table_block } => {
            let file_entry_address = superblock.blocks_ptr + inode_table_block as u64 * BLOCK_SIZE as u64;

            let parent_file_entries = get_file_struct::<DirectoryBlock, 0x1000>(img_file, file_entry_address)?;
            
            for i in 0..item_count {
                let entry = parent_file_entries.file_entries[i as usize];

                if helpers::get_string_from_array(&entry.filename) == filename {
                    file_inode_address = entry.file_inode_ptr;

                    break;
                }
            }

            if file_inode_address == 0 {
                return Err(format!("File {} not found in {}.", filename, dir));
            }
        },
    }

    let file_inode = get_inode(img_file, file_inode_address)?;

    let (filesize, file_direct_ptrs, file_indirect_ptr) = match file_inode.subtype_info {
        INodeSubtype::File { size, direct_block_ptrs, indirect_ptr } => (size, direct_block_ptrs, indirect_ptr),
        INodeSubtype::Directory { .. } => return Err(format!("{} is a directory, not a file!", filename)),
    };

    let file_blocks = file_inode.get_blocks_used();

    let path = file_to_write.as_path();

    let mut file = match File::create(path) {
        Ok(v) => v,
        Err(why) => return Err(format!("Couldn't create file {}: {}", path.to_str().unwrap(), why))
    };

    match file.set_len(filesize as u64) {
        Ok(_) => (),
        Err(why) => return Err(format!("Failed to create file {} with size {}: {}", path.to_str().unwrap(), filesize, why)),
    };
   
    let mut bytes_left = filesize;

    for i in 0..(std::cmp::min(file_blocks, 8)) {
        let mut buf = vec![0u8; std::cmp::min(bytes_left as usize, 0x1000)];

        match img_file.read_exact_at(&mut buf, superblock.blocks_ptr + file_direct_ptrs[i as usize] as u64 * BLOCK_SIZE as u64) {
            Ok(_) => (),
            Err(why) => return Err(format!("Failed reading file blocks: {}", why)),
        }
        
        match file.write_all(&buf) {
            Ok(_) => (),
            Err(why) => return Err(format!("Failed writing to file: {}", why)),
        }

        bytes_left -= std::cmp::min(0x1000, bytes_left);
    }

    if file_indirect_ptr > 0 {
        let file_indirect_ptr = superblock.blocks_ptr + file_indirect_ptr as u64 * BLOCK_SIZE as u64;
        
        let mut blocks_left_to_read = (bytes_left + BLOCK_SIZE - 1) / BLOCK_SIZE;

        let block_blocks_left_to_read = blocks_left_to_read + 0x3FF / 0x400;
        
        let first_layer = get_file_struct::<FileFirstIndirectBlock, 0x1000>(img_file, file_indirect_ptr)?;

        for i in 0..block_blocks_left_to_read {
            let second_layer_indirect_ptr = first_layer.more_indirect_blocks[i as usize];
            let second_layer_indirect_ptr = superblock.blocks_ptr + second_layer_indirect_ptr as u64 * BLOCK_SIZE as u64;
            let second_layer = get_file_struct::<FileSecondIndirectBlock, 0x1000>(img_file, second_layer_indirect_ptr)?;

            for j in 0..(std::cmp::min(blocks_left_to_read, 0x400)) {
                let block_ptr = second_layer.blocks[j as usize];
                let block_ptr = superblock.blocks_ptr + block_ptr as u64 * BLOCK_SIZE as u64;

                let mut buf = vec![0u8; std::cmp::min(bytes_left as usize, 0x1000)];
                
                match img_file.read_exact_at(&mut buf, block_ptr) {
                    Ok(()) => (),
                    Err(why) => return Err(format!("Failed to read file block at {}: {}", block_ptr, why)),
                }

                match file.write_all(&mut buf) {
                    Ok(()) => (),
                    Err(why) => return Err(format!("Failed to write file block: {}", why))
                }

                blocks_left_to_read -= 1;
            }
        }
    }
    
    update_superblock(img_file)?;

    Ok(())
}

pub fn remove(file: &mut File, dir: &String) -> Result<(), String> {
    let superblock = get_superblock(file)?;
   
    let dir = String::from(dir.trim().trim_matches('/'));

    if dir == "" || dir == "/" {
        return Err(format!("Cannot delete root!"))
    }

    let dir_split = dir.split('/').collect::<Vec<&str>>();

    let filename = match dir_split.last() {
        Some(v) => v.to_owned(),
        None => return Err(format!("Cannot delete at empty path \"{}\".", dir))
    };

    if filename == "." || filename == ".." {
        return Err(format!("Cannot remove directory links like {}", filename));
    }

    let parent_path = dir_split[0..(dir_split.len()-1)].join("/");

    let parent_inode_address = if parent_path == "" {
        superblock.inode_blocks_ptr
    }
    else {
        match find_folder_inode(file, &parent_path)? {
            Some(v) => v,
            None => return Err(format!("Directory {} does not exist.", parent_path))
        }
    };

    let mut dir_inode = get_inode(file, parent_inode_address)?;
    
    dir_inode.last_accessed = helpers::get_current_timestamp();
    
    let mut item_inode_address = 0u64;

    match dir_inode.subtype_info {
        INodeSubtype::File { .. } => return Err(format!("{} is a file, not a directory.", &parent_path)),
        INodeSubtype::Directory { ref mut item_count, inode_table_block } => {
            let file_entry_address = superblock.blocks_ptr + inode_table_block as u64 * BLOCK_SIZE as u64;

            let parent_file_entries = get_file_struct::<DirectoryBlock, 0x1000>(file, file_entry_address)?;
            
            for i in 0..*item_count {
                let entry = parent_file_entries.file_entries[i as usize];

                if helpers::get_string_from_array(&entry.filename) == filename {
                    item_inode_address = entry.file_inode_ptr;
                    
                    // check what to delete first, before removing any access to it in case of error
                    let mut item_inode = get_inode(file, item_inode_address)?;

                    match item_inode.subtype_info {
                        INodeSubtype::Directory { item_count, inode_table_block } => {
                            if item_inode.link_count > 2 {
                                item_inode.link_count -= 1;

                                match file.write_all_at(&(match bincode::serialize(&item_inode) {
                                        Ok(b) => b,
                                        Err(why) => return Err(format!("Couldn't serialize inode: {}", why))
                                    }), item_inode_address) {
                                    Ok(()) => (),
                                    Err(why) => return Err(format!("Couldn't write inode: {}", why)),
                                }
                            }
                            else {
                                if item_count > 2 {
                                    return Err(format!("Directory {} not empty!", filename));
                                }

                                set_blocks_used(file, superblock.blocks_ptr + inode_table_block as u64 * BLOCK_SIZE as u64, 1, false)?; 

                                set_inode_used(file, item_inode_address, false)?;
                            }
                        },
                        INodeSubtype::File { size: _, direct_block_ptrs, indirect_ptr } => {
                            if item_inode.link_count > 1 {
                                item_inode.link_count -= 1;

                                match file.write_all_at(&(match bincode::serialize(&item_inode) {
                                        Ok(b) => b,
                                        Err(why) => return Err(format!("Couldn't serialize inode: {}", why))
                                    }), item_inode_address) {
                                    Ok(()) => (),
                                    Err(why) => return Err(format!("Couldn't write inode: {}", why)),
                                }
                            }
                            else {
                                let file_blocks = item_inode.get_blocks_used();

                                // I could just clean it in a single block as it is, but cleaning it block by block
                                // allows for more flexible allocation patterns in the future

                                let mut blocks_left_to_free = file_blocks;
                                
                                for i in 0..(std::cmp::min(blocks_left_to_free, 8)) {
                                    set_blocks_used(file, superblock.blocks_ptr + direct_block_ptrs[i as usize] as u64 * BLOCK_SIZE as u64, 1, false)?;

                                    blocks_left_to_free -= 1;
                                }

                                if indirect_ptr > 0 {
                                    let file_indirect_ptr = superblock.blocks_ptr + indirect_ptr as u64 * BLOCK_SIZE as u64;

                                    let block_blocks_left_to_free = (blocks_left_to_free + 0x3FF) / 0x400;

                                    dbg!(&block_blocks_left_to_free);
                            
                                    let first_layer = get_file_struct::<FileFirstIndirectBlock, 0x1000>(file, file_indirect_ptr)?;

                                    for i in 0..block_blocks_left_to_free {
                                        let second_layer_indirect_ptr = first_layer.more_indirect_blocks[i as usize];
                                        let second_layer_indirect_ptr = superblock.blocks_ptr + second_layer_indirect_ptr as u64 * BLOCK_SIZE as u64;
                                        let second_layer = get_file_struct::<FileSecondIndirectBlock, 0x1000>(file, second_layer_indirect_ptr)?;

                                        for j in 0..(std::cmp::min(blocks_left_to_free, 0x400)) {
                                            let block_ptr = second_layer.blocks[j as usize];
                                            let block_ptr = superblock.blocks_ptr + block_ptr as u64 * BLOCK_SIZE as u64;

                                            dbg!(&block_ptr);
                                            set_blocks_used(file, block_ptr, 1, false)?;
                                        
                                            blocks_left_to_free -= 1;
                                        }

                                        set_blocks_used(file, second_layer_indirect_ptr, 1, false)?;
                                    }

                                    set_blocks_used(file, file_indirect_ptr, 1, false)?;
                                }

                                set_inode_used(file, item_inode_address, false)?;
                            }
                        },
                    };

                    // have to reorder file entries
                    
                    if item_inode_address == superblock.inode_blocks_ptr {
                        return Err(format!("Cannot delete root"))
                    }
                    
                    let mut new_file_entries = DirectoryBlock {
                        file_entries: [DirectoryFileEntry {
                            file_inode_ptr: 0,
                            filename: [0u8; 56]
                        }; 0x40]
                    };

                    let mut index = 0usize;

                    for j in 0..*item_count {
                        if j != i {
                            new_file_entries.file_entries[index] = parent_file_entries.file_entries[j as usize];

                            index += 1;
                        }
                    }

                    *item_count -= 1;

                    match file.write_all_at(&(match bincode::serialize(&new_file_entries) {
                            Ok(b) => b,
                            Err(why) => return Err(format!("Couldn't serialize dir block: {}", why))
                        }), file_entry_address) {
                        Ok(()) => (),
                        Err(why) => return Err(format!("Couldn't write dir block: {}", why)),
                    }

                    break;
                }
            }

            if item_inode_address == 0 {
                return Err(format!("Item {} not found in {}.", filename, dir));
            }
        },
    }

    match file.write_all_at(&(match bincode::serialize(&dir_inode) {
            Ok(b) => b,
            Err(why) => return Err(format!("Couldn't serialize directory inode: {}", why))
        }), parent_inode_address) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't write directory inode: {}", why)),
    }

    update_superblock(file)?;

    Ok(())

}

pub fn create_link(img_file: &mut File, file: &String, link: &String) -> Result<(), String> {
    let superblock = get_superblock(img_file)?;

    let link_path = String::from(link.trim().trim_matches('/'));
    let link_path_split = link_path.split('/').collect::<Vec<&str>>();

    let linkname = match link_path_split.last() {
        Some(v) => v.to_owned(),
        None => return Err(format!("Cannot link file with empty name \"{}\".", link_path))
    };

    let parent_path = link_path_split[0..(link_path_split.len()-1)].join("/");

    let parent_inode_address = if parent_path == "" {
        superblock.inode_blocks_ptr
    }
    else {
        match find_folder_inode(img_file, &parent_path)? {
            Some(v) => v,
            None => return Err(format!("Directory {} does not exist.", parent_path))
        }
    };

    let linkname_vec: Vec<u8> = String::from(linkname).into_bytes();

    let mut linkname_bytes = [0u8; 56];
        
    for i in 0..(std::cmp::min(linkname_vec.len(), 56)) {
        linkname_bytes[i] = linkname_vec[i];
    }

    let mut dir_inode = get_inode(img_file, parent_inode_address)?;
    
    dir_inode.last_accessed = helpers::get_current_timestamp();

    let inode_to_link_to_address = match find_folder_inode(img_file, file)? {
        None => return Err(format!("Cannot link to {}: Doesn't exist", file)),
        Some(v) => v
    };

    let mut inode_to_link_to = get_inode(img_file, inode_to_link_to_address)?;
    
    match dir_inode.subtype_info {
        INodeSubtype::File { .. } => return Err(format!("{} is a file, not a directory.", &parent_path)),
        INodeSubtype::Directory { ref mut item_count, inode_table_block } => {
            let file_entry_address = superblock.blocks_ptr + inode_table_block as u64 * BLOCK_SIZE as u64;

            let mut parent_file_entries = get_file_struct::<DirectoryBlock, 0x1000>(img_file, file_entry_address)?;
            
            for entry in parent_file_entries.file_entries {
                if entry.filename == linkname_bytes {
                    return Err(format!("Directory/file {} already exists in {}", &linkname, parent_path));
                }
            }

            parent_file_entries.file_entries[*item_count as usize] = DirectoryFileEntry {
                filename: linkname_bytes,
                file_inode_ptr: inode_to_link_to_address
            };

            inode_to_link_to.link_count += 1;

            match img_file.write_all_at(&(match bincode::serialize(&inode_to_link_to) {
                    Ok(b) => b,
                    Err(why) => return Err(format!("Couldn't serialize updated inode: {}", why))
                }), inode_to_link_to_address) {
                Ok(()) => (),
                Err(why) => return Err(format!("Couldn't write updated inode: {}", why)),
            }

            *item_count += 1;
                
            match img_file.write_all_at(&(match bincode::serialize(&parent_file_entries) {
                    Ok(b) => b,
                    Err(why) => return Err(format!("Couldn't serialize dir block: {}", why))
                }), file_entry_address) {
                Ok(()) => (),
                Err(why) => return Err(format!("Couldn't write dir block: {}", why)),
            }
        },
    }

    match img_file.write_all_at(&(match bincode::serialize(&dir_inode) {
            Ok(b) => b,
            Err(why) => return Err(format!("Couldn't serialize directory inode: {}", why))
        }), parent_inode_address) {
        Ok(()) => (),
        Err(why) => return Err(format!("Couldn't write directory inode: {}", why)),
    }

    Ok(())
}

/// Lists directory <dir> in virtual disk <file> content along with basic info about members
pub fn list(file: &mut File, dir: &String) -> Result<(), String> {
    let superblock = get_superblock(file)?;
    
    let dir = String::from(dir.trim_matches('/'));
    let dir_address = if dir == "" || dir == "/" { 
        superblock.inode_blocks_ptr
    }
    else {
        match find_folder_inode(file, &dir)? {
            None => return Err(format!("Item {} is not a directory.", &dir)),
            Some(dir_address) => dir_address
        }
    };

    let dir_inode = get_inode(file, dir_address)?;

    let (block_address, item_count) = match dir_inode.subtype_info {
        INodeSubtype::File { .. } => return Err(format!("{} is a file!", dir)),
        INodeSubtype::Directory { item_count, inode_table_block } => (inode_table_block, item_count)
    };

    let dir_block = get_file_struct::<DirectoryBlock, 0x1000>(file, superblock.blocks_ptr + block_address as u64 * BLOCK_SIZE as u64)?;
    
    println!("Contents of {}:", &dir);

    for i in 0..item_count {
        let item = dir_block.file_entries[i as usize];

        let name = helpers::get_string_from_array(&item.filename);
        let item_inode = get_inode(file, item.file_inode_ptr)?;

        let data = match item_inode.subtype_info {
            INodeSubtype::File { size, ..  } => format!("File\tSize: {}\tBlocks used: {}", size, item_inode.get_blocks_used()),
            INodeSubtype::Directory { item_count, .. } => format!("Directory\tItem count: {}", item_count)
        };

        println!("{}\t\t{}", name, data);
    }

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

/// Returns a pointer to the first section of `block_count` blocks
pub fn find_free_blocks(file: &mut File, block_count: u32) -> Result<u64, String> {
    let superblock = get_superblock(file)?;

    let mut block_bitmap_bytes = [0u8; BLOCK_SIZE as usize];

    let bitmap_block_count = (superblock.inode_bitmap_ptr - superblock.block_bitmap_ptr) / BLOCK_SIZE as u64;

    let mut free_blocks_ptr: u64 = 0;

    'block_loop: for i in 0..bitmap_block_count {
        match file.read_exact_at(&mut block_bitmap_bytes, superblock.block_bitmap_ptr + i * BLOCK_SIZE as u64) {
            Ok(_) => (),
            Err(why) => return Err(format!("Failed to read block bitmap: {}", why))
        }

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

fn set_blocks_used(file: &mut File, block_ptr: u64, block_count: u64, used: bool) -> Result<(), String> {
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
            if used {
                byte |= mask;
            }
            else {
                byte &= !mask;
            }
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

        let mut ptr = 0usize;
        for byte in block_bitmap_bytes {
            let mut mask = 0x80u8;

            while mask != 0 {
                if byte & mask == 0 {
                    free_inode_ptr = superblock.inode_blocks_ptr + ((i * BLOCK_SIZE as u64) * 8 + ptr as u64) * INODE_SIZE as u64;
                    break 'block_loop; 
                }

                mask /= 2;
                ptr += 1;
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

fn set_inode_used(file: &mut File, inode_ptr: u64, used: bool) -> Result<(), String> {
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

    if used {
        inode_bitmap_byte[0] |= mask;
    }
    else {
        inode_bitmap_byte[0] &= !mask;
    }

    match file.write_at(&inode_bitmap_byte, inode_bitmap_byte_address) {
        Ok(_) => (),
        Err(why) => return Err(format!("Couldn't write bitmap: {}", why)),
    };
    

    Ok(())
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

/// Util function. Garbage in, garbage out, use at your own caution.
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
                if byte & mask != 0 {
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
