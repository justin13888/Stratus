pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

pub fn format_timestamp(timestamp: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(timestamp as i64, 0);
    match dt {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "-".to_string(),
    }
}
