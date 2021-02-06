# PWDeck

![Build status](https://github.com/protoshark/pwdeck/workflows/Rust/badge.svg)

<div style="text-align: center"><img src="./assets/logo.svg" /></div>

## What is this

`pwdeck` is an tool to manage and generate passwords.
It is designed to be simple and secure.

This project is made with educational purposes, so, it's not recommended for daily usage.
Feel free to contribute and tell me some good pratices about cryptography and password security.

## How to use it

`pwdeck` is designed to be simple, the front-end design is not finished yet, and might be changed soon.
For now, it exposes the `pwdeck` command.

### Generating random passwords

```
pwdeck generate --help
USAGE:
    pwdeck generate [OPTIONS] [method]

FLAGS:
    -h, --help
            Prints help information


OPTIONS:
    -s, --size <size>
            The size of the generated password. For random, the default is 25 characters, and for diceware is 5 words

    -w, --wordlist <wordlist>
            The wordlist to be used with diceware


ARGS:
    <method>
            The generation method (random or diceware) [default: random]
```

The `pwdeck generate` command generates a random password for you, and return it to the stdout.
For exaple, for generating a password with random characters you can run simply run:

```
pwdeck generate
3/++Zf2VPjJZqK1/=8oRo?h4=
```

<sup>You can use the `--size` flag to change the password length.</sup>

`pwdeck` also allow you to generate passwords using the [diceware](https://en.wikipedia.org/wiki/Diceware) alghorithm
(which, in short, rolls some dices and map their values with some word).

<sup>You need to pass a wordlist file with the `--wordlist` flag.</sup>

```
pwdeck generate diceware -w path/to/diceware/wordlist
```

<sup>You can also pass the `--size` flag to change the amount of words.</sup>

### Storing passwords

```
pwdeck new --help
USAGE:
    pwdeck new --service <service> --username <username>

FLAGS:
    -h, --help    Prints help information

OPTIONS:
    -s, --service <service>      The name of the service
    -u, --username <username>    The username to use
```
