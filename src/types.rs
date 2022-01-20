use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;

use std::fmt;

pub const MAGIC_WRSFS: u32 = 0x46535257;

pub const BLOCK_SIZE: u32 = 0x1000;
pub const BLOCK_BITMAP_SIZE_DESCRIBED: u32 = BLOCK_SIZE * BLOCK_SIZE * 8;
pub const INODE_SIZE: u32 = 0x40;
pub const INODE_SIZE_DESCRIBED: u32 = 0x4000;
pub const INODE_BITMAP_SIZE_DESCRIBED: u64 = BLOCK_SIZE as u64 * 8u64 * INODE_SIZE_DESCRIBED as u64;
pub const INODE_BLOCK_SIZE_DESCRIBED: u32 = BLOCK_SIZE / INODE_SIZE * INODE_SIZE_DESCRIBED;

pub const SMALLEST_IMAGE_SIZE: u64 = 0x100000;

#[derive(Serialize, Deserialize, Debug)]
pub enum INodeSubtype {
    File {
        size: u32,
        blocks: u8,
        direct_block_ptrs: [u32; 8],
        indirect_ptr: u32
    },
    Directory {
        item_count: u8,
        inode_table_block_ptr: [u32; 8]
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct INode {
    pub created_time: u64,
    pub last_accessed: u64,
    pub link_count: u8,
    pub subtype_info: INodeSubtype
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectoryFileEntry {
    #[serde(with = "BigArray")]
    pub filename: [u8; 60],
    pub file_inode_ptr: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectoryBlock {
    #[serde(with = "BigArray")]
    pub file_entries: [DirectoryFileEntry; 0x40] 
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Superblock {
    pub magic: u32, // hardcoded
    pub block_size: u32, // hardcoded
    pub block_count: u32,
    pub block_free: u32,
    pub created_time: u64,
    pub last_accessed_time: u64,
    pub inode_size: u32, // hardcoded
    pub inode_count: u32,
    pub inode_block_count: u32,
    pub inode_free: u32,
    pub inode_bitmap_ptr: u64,
    pub block_bitmap_ptr: u64,
    pub inode_blocks_ptr: u64,
    pub blocks_ptr: u64
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FsBitmapBlock {
    #[serde(with = "BigArray")]
    bitmap: [u8; 0x1000]
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FsBitmap {
    full_bitmap: Vec<FsBitmapBlock>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct INodeBlock {
    #[serde(with = "BigArray")]
    inodes: [INode; 64]
}

#[derive(Serialize, Deserialize, Debug)]
pub struct INodes {
    full_inodes: Vec<INodeBlock>
}

impl Superblock {
    pub fn create(size: u64) -> Superblock {
        let bitmap_block_count = ((size + BLOCK_BITMAP_SIZE_DESCRIBED as u64 - 1) / BLOCK_BITMAP_SIZE_DESCRIBED as u64) as u32; 
        let inode_bitmap_block_count = ((size + INODE_BITMAP_SIZE_DESCRIBED - 1) / INODE_BITMAP_SIZE_DESCRIBED) as u32;
        let inode_block_count = ((size + INODE_BLOCK_SIZE_DESCRIBED as u64 - 1) / INODE_BLOCK_SIZE_DESCRIBED as u64) as u32;

        let block_count = (size / BLOCK_SIZE as u64) as u32;

        let current_time = SystemTime::now();
        let current_time = current_time.duration_since(UNIX_EPOCH).expect("Datetime error").as_secs();

        let mut sb = Superblock {
            magic: MAGIC_WRSFS,
            block_size: 0x1000,
            block_count,
            block_free: block_count,
            created_time: current_time,
            last_accessed_time: current_time,
            inode_size: INODE_SIZE,
            inode_count: inode_block_count * (BLOCK_SIZE / INODE_SIZE),
            inode_block_count,
            inode_free: inode_block_count * (BLOCK_SIZE / INODE_SIZE),
            inode_bitmap_ptr: (BLOCK_SIZE * (1 + bitmap_block_count)) as u64,
            block_bitmap_ptr: (BLOCK_SIZE * 1) as u64,
            inode_blocks_ptr: (BLOCK_SIZE * (1 + bitmap_block_count + inode_block_count)) as u64,
            blocks_ptr: (BLOCK_SIZE * (1 + bitmap_block_count + inode_bitmap_block_count + inode_block_count)) as u64,
        };

        sb.block_free -= (sb.blocks_ptr / BLOCK_SIZE as u64) as u32;

        sb
    }
}

impl fmt::Display for FsBitmapBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, v) in (&(self.bitmap)).iter().enumerate() {
            write!(f, "{:08b}", v)?;

            if i % 32 == 0 {
                write!(f, "\n")?;
            }
        }
        
        write!(f, "\n")
    }
}

impl fmt::Display for FsBitmap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in &self.full_bitmap {
            write!(f, "{}", b)?;
        }
        write!(f, "\n")
    }
}
