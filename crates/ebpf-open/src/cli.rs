use std::path::PathBuf;

const USAGE: &str = "\
ebpf-open - eBPF openat syscall monitor & interceptor

USAGE:
    ebpf-open [OPTIONS]

OPTIONS:
    -c <path>       Config file path (default: ./config.toml)
    --btf <path>    Custom BTF file path
    -q              Quiet mode, only print errors
    -v              Verbose: show monitor events
    -vv             Very verbose: show debug info
    -s <path>       Run as daemon, log output to file
    -h, --help      Show this help message";

pub struct CliArgs {
    pub config_path: Option<PathBuf>,
    pub btf_path: Option<PathBuf>,
    pub verbosity: u8,
    pub log_file: Option<PathBuf>,
}

pub fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut btf_path = None;
    let mut verbosity: u8 = 1;
    let mut log_file = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-q" => {
                verbosity = 0;
                i += 1;
            }
            "-vv" => {
                verbosity = 3;
                i += 1;
            }
            "-v" => {
                verbosity = 2;
                i += 1;
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-c" if i + 1 < args.len() => {
                config_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--btf" if i + 1 < args.len() => {
                btf_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-s" if i + 1 < args.len() => {
                log_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-c" | "--btf" | "-s" => {
                eprintln!("error: {} requires a value", args[i]);
                std::process::exit(1);
            }
            other => {
                eprintln!("error: unknown option '{other}'");
                eprintln!("{USAGE}");
                std::process::exit(1);
            }
        }
    }

    if config_path.is_none() {
        let default_path = PathBuf::from("config.toml");
        if default_path.exists() {
            config_path = Some(default_path);
        }
    }

    CliArgs {
        config_path,
        btf_path,
        verbosity,
        log_file,
    }
}
