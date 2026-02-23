pub use plain;

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_PATH_LEN: usize = 256;

#[repr(C)]
pub struct PrintEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub syscall_nr: u32,
    pub ret: i64,
    pub comm: [u8; TASK_COMM_LEN],
    pub fname: [u8; MAX_PATH_LEN],
}

impl Default for PrintEvent {
    fn default() -> Self {
        Self {
            pid: 0, tid: 0, uid: 0, syscall_nr: 0, ret: 0,
            comm: [0u8; TASK_COMM_LEN],
            fname: [0u8; MAX_PATH_LEN],
        }
    }
}

unsafe impl plain::Plain for PrintEvent {}

#[repr(C)]
pub struct InterceptEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub from: [u8; MAX_PATH_LEN],
    pub to: [u8; MAX_PATH_LEN],
    pub write_ret: i32,
}

impl Default for InterceptEvent {
    fn default() -> Self {
        Self {
            pid: 0, tid: 0, uid: 0,
            comm: [0u8; TASK_COMM_LEN],
            from: [0u8; MAX_PATH_LEN],
            to: [0u8; MAX_PATH_LEN],
            write_ret: 0,
        }
    }
}

unsafe impl plain::Plain for InterceptEvent {}
