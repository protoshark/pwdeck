extern crate clap;
extern crate nanoid;
extern crate rand;
extern crate serde;

use pwdeck::cli::CLI;

fn main() {
    let _ = CLI::from_args().run();
}
