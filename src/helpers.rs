use std::time::{UNIX_EPOCH, SystemTime};

pub fn get_current_timestamp() -> u64 {
    let current_time = SystemTime::now();
    current_time.duration_since(UNIX_EPOCH).expect("Datetime error").as_secs()
}

pub fn get_string_from_array(buf: &[u8]) -> String {
    let null_pos = buf.iter().position(|&c| c == 0u8);

    let proper_slice = match null_pos {
        None => buf,
        Some(i) => &buf[0..i]
    };

    String::from_utf8(proper_slice.to_vec()).expect("SHIT")
}
