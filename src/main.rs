#[macro_use]
extern crate clap;

fn main() {
    let yaml = load_yaml!("options.yml");
    let args = clap::App::from_yaml(yaml).get_matches();
    let target_pid = args.value_of("pid").unwrap().parse::<i32>().unwrap_or_else(|e| {
        eprintln!("received the invalid pid. {}", e);
        println!("{}", args.usage());
        std::process::exit(1);
    });

    let pid_max = procfs::sys::kernel::pid_max().unwrap();
    if target_pid == 0 || target_pid > pid_max {
        eprintln!("received the invalid pid");
        println!("{}", args.usage());
        std::process::exit(1);
    }
}
