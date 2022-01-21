use std::time::{UNIX_EPOCH, SystemTime};

pub fn get_current_timestamp() -> u64 {
    let current_time = SystemTime::now();
    current_time.duration_since(UNIX_EPOCH).expect("Datetime error").as_secs()
}
