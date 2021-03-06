// TODO: 
//  - CLI tests
//  - Replace clap? (with a lighweight one)
//  - Refactory
//  - Better command interface

use std::{
    fs::{File, OpenOptions},
    io,
};

use clap::{AppSettings, Arg, SubCommand};

use crate::{
    generator::{GenerationMethod, Generator},
    password::Entry,
    vault::Vault,
};

pub struct CLI<'a>(clap::ArgMatches<'a>);

impl<'a> CLI<'a> {
    pub fn from_args() -> Self {
        let app = clap::App::new("pwdeck")
            .version("0.1.0")
            .author("Protoshark <protoshark@pm.me>")
            .about("A simple password manager")
            .after_help("NOTE: The vault file can be configured via PWDECK_VAULT environment variable")
            .settings(&[
                AppSettings::GlobalVersion,
                AppSettings::DisableHelpSubcommand,
                AppSettings::ArgsNegateSubcommands,
                AppSettings::SubcommandRequiredElseHelp,
            ])
            // pwdeck generate
            .subcommand(
                SubCommand::with_name("generate")
                    .setting(clap::AppSettings::DisableVersion)
                    .about("Generate a password")
                    .arg(Arg::with_name("method")
                            .default_value("random")
                            .multiple(false)
                            .help("The generation method (random or diceware)")
                            .display_order(0)
                    ).arg(Arg::with_name("size")
                            .long("size")
                            .short("s")
                            .help("The size of the generated password.")
                            .long_help("The size of the generated password. For random, the default is 25 characters, and for diceware is 5 words")
                            .takes_value(true)
                            .display_order(2)
                    ).arg(Arg::with_name("wordlist")
                            .long("wordlist")
                            .short("w")
                            .help("The wordlist to be used with diceware")
                            .takes_value(true)
                            .display_order(3)
                            .required_if("method", "diceware")
                    ).display_order(0),
            )
            // pwdeck new
            .subcommand(
                SubCommand::with_name("new")
                    .setting(clap::AppSettings::DisableVersion)
                    .about("Save a password to the vault")
                    .arg(Arg::with_name("service")
                            .long("service")
                            .short("s")
                            .help("The name of the service")
                            .required(true)
                            .takes_value(true)
                            .display_order(0),
                    ).arg(Arg::with_name("username")
                            .long("username")
                            .short("u")
                            .help("The username to use")
                            .required(true)
                            .takes_value(true)
                            .display_order(1),
                    ).display_order(1),
            )
            // pwdeck list
            .subcommand(
                    SubCommand::with_name("get")
                    .setting(clap::AppSettings::DisableVersion)
                    .about("List vault entries")
                    .arg(Arg::with_name("id")
                        .help("The entry ID to get the password")
                        .takes_value(true)
                    ).arg(Arg::with_name("service")
                        .long("service")
                        .short("s")
                        .help("Filter entries matching service")
                        .takes_value(true)
                        .display_order(0)
                    ).arg(Arg::with_name("username")
                        .long("username")
                        .short("u")
                        .help("Filter entries matching username")
                        .takes_value(true)
                        .display_order(1)
                    )
            );
        // TODO: more commands such as export, import, ...

        Self(app.get_matches())
    }

    pub fn run(self) {
        let args = self.0;
        // let vault_file = args.value_of("file").unwrap_or(DEFAULT_VAULT_PATH);

        // println!("{}", vault_file);

        match args.subcommand() {
            ("generate", Some(generate_args)) => handle_generate(generate_args),
            ("new", Some(new_args)) => handle_new(new_args),
            ("get", Some(list_args)) => handle_get(list_args),
            _ => {}
        }
    }
}

fn handle_generate(args: &clap::ArgMatches) {
    // parse the password size
    let password_size: Option<usize> = if let Some(size) = args.value_of("size") {
        Some(size.parse().unwrap_or_else(|_| {
            eprintln!("Invalid size: {}", size);
            std::process::exit(1);
        }))
    } else {
        None
    };

    // parse the generation method
    let generation_method = match args.value_of("method") {
        Some("random") | None => GenerationMethod::Random(password_size.unwrap_or(25)),
        Some("diceware") => {
            let worlist_path = args.value_of("wordlist").unwrap();
            GenerationMethod::Diceware(worlist_path.to_string(), password_size.unwrap_or(5))
        }
        Some(other) => {
            eprintln!("Invalid generation method: {}", other);
            std::process::exit(1);
        }
    };

    // generate the password
    let password_generator = Generator::from(generation_method);
    let password = password_generator.password().unwrap();

    // print the generated password
    print!("{}", *password);
}

fn prompt_master(msg: &'static str) -> io::Result<String> {
    rpassword::read_password_from_tty(Some(msg))
}

fn handle_new(args: &clap::ArgMatches) {
    let vault_path = crate::vault_path();

    let try_open = || OpenOptions::new().write(true).read(true).open(&vault_path);

    let (mut vault, mut vault_file) = match try_open() {
        Ok(mut file) => {
            // vault exists
            let master = prompt_master("master password: ").unwrap();

            // return the vault from the file
            // TODO: check if the file is a valid vault (i.e. error handling)
            let vault = Vault::from_file(&mut file, &master).unwrap();

            (vault, file)
        }
        Err(error) => {
            match error.kind() {
                io::ErrorKind::NotFound => {
                    println!("Vault doesn't exists, creating a new one.");

                    // create a new master password and confirm it
                    let master = prompt_master("master_password: ").unwrap();
                    let repeat = prompt_master("confirm the password: ").unwrap();

                    // check if the passwords matches
                    if master != repeat {
                        eprintln!("Passwords doesn't match");
                        std::process::exit(1);
                    }

                    // create the vault file
                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(&vault_path)
                        .unwrap_or_else(|error| {
                            eprintln!("Couldn't create a new file: {}.", error);
                            std::process::exit(1);
                        });

                    // create the new vault
                    let vault = Vault::new(&master);

                    (vault, file)
                }
                error => panic!("Could not open the vault: {:?}.", error),
            }
        }
    };

    // get the password entry info
    let service = args.value_of("service").unwrap();
    let username = args.value_of("username").unwrap();

    // SAFETY: this is safe only if running on unix
    // TODO: pipe feature only if target_family=unix
    let isatty = unsafe { crate::ffi::isatty(0) } == 1;

    // get the password from stdin (checking if running from pipe)
    let password = if isatty {
        // the process is running with no pipes
        rpassword::prompt_password_stdout("password: ").unwrap()
    } else {
        // the process is running from a pipe
        // don't display any message
        rpassword::read_password().unwrap()
    };

    // create the entry
    let entry = Entry::new(username, &password);

    // add the new entry to the vault
    vault.insert_entry(service, entry).unwrap();
    // sync the file
    vault.sync(&mut vault_file).unwrap();
}

fn handle_get(args: &clap::ArgMatches) {
    let vault_path = crate::vault_path();

    let mut vault_file = File::open(&vault_path).unwrap_or_else(|error| match error.kind() {
        io::ErrorKind::NotFound => {
            eprintln!("Vault not found: '{}'.", vault_path);
            std::process::exit(1);
        }
        _ => panic!("Could not read the vault."),
    });

    let master = prompt_master("master password: ").unwrap();
    let vault = Vault::from_file(&mut vault_file, &master).unwrap();

    if let Some(id) = args.value_of("id") {
        let groups = &vault.schema().passwords;

        // search for the entry with the given ID
        for (_, entries) in groups {
            if let Some(entry) = entries.iter().find(|a| a.id() == id){
                // entry found, print its password
                let password: &String = &entry.password(); // deref cohersion
                print!("{}", password);

                // exit
                return;
            }
        }

        // exit with error
        eprintln!("Could not find the given ID");
        std::process::exit(1);

    } else {
        let _filter_service = args.value_of("service");
        let _filter_username = args.value_of("username");

        let entries = &vault.schema().passwords;

        for (group, entries) in entries.iter() {
            println!("{}:", group);
            let last_entry = entries.len().saturating_sub(1);
            for (i, entry) in entries.iter().enumerate() {
                let tree_char = if i < last_entry { '├' } else { '└' };
                println!("  {}── {}", tree_char, entry.name());
            }
        }

        println!("")
    }
}


