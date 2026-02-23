use std::sync::atomic::{AtomicU8, Ordering};

static VERBOSITY: AtomicU8 = AtomicU8::new(1);

pub fn init(verbosity: u8) {
    VERBOSITY.store(verbosity, Ordering::Relaxed);
}

pub fn verbosity() -> u8 {
    VERBOSITY.load(Ordering::Relaxed)
}

/// 级别 >= 1 输出（默认级别即可见）
macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::log::verbosity() >= 1 {
            println!($($arg)*);
        }
    };
}
pub(crate) use info;

/// 级别 >= 2 输出（-v）
macro_rules! verbose {
    ($($arg:tt)*) => {
        if $crate::log::verbosity() >= 2 {
            println!($($arg)*);
        }
    };
}
pub(crate) use verbose;

/// 级别 >= 3 输出（-vv）
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::verbosity() >= 3 {
            println!($($arg)*);
        }
    };
}
pub(crate) use debug;
