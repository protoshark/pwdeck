extern crate rand;
extern crate nanoid;
extern crate serde;
extern crate clap;

use pwdeck::cli::CLI;

fn main() {
    let _ = CLI::from_args().run();
}
