#[macro_use]
extern crate clap;

fn main() {
    let args = clap::App::from_yaml(load_yaml!("options.yml")).get_matches();
}
