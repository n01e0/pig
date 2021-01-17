#[macro_use]
extern crate clap;

fn main() {
    let app = clap_app!(pig =>
        (name:          crate_name!())
        (version:       crate_version!())
        (author:        crate_authors!())
        (about:         crate_description!())
    ).get_matches();
}
