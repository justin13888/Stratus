pub fn format_size(bytes: u64) -> String {
    use humansize::{BINARY, format_size};
    format_size(bytes, BINARY)
}

pub fn format_timestamp(timestamp: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(timestamp as i64, 0);
    match dt {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "-".to_string(),
    }
}
