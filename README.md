# Password Generator

A simple password generation tool

## Usage

### Command line version

```sh
Usage: password_gen [OPTIONS] INPUT KEY
Options:
  -a, --algorithm ALGO    Hash algorithm (SHA256 or SHA512, default: SHA256)
  -l, --length LENGTH     Password length (8-32, default: 12)
  -c, --case CASE         Case conversion (none, lower, upper, default: none)
  -h, --help              Show this help message
```

#### Examples

- Generate a password with default settings:
  ```sh
  pw_gen "user@example.com" "mykey"
  ```

- Generate a 16-character password using SHA-512 and convert to lowercase:
  ```sh
  pw_gen -a SHA512 -l 16 -c lower "user@example.com" "mykey"
  ```

### Web version

[Download](pw_gen.html) and open with your browser

Note: Depends on [Web Crypto API](https://developer.mozilla.org/docs/Web/API/Web_Crypto_API)

## License

[LICENSE](LICENSE)
