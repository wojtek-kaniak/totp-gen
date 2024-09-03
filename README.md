# [TOTP](https://datatracker.ietf.org/doc/html/rfc6238) CLI generator

> [!WARNING]
> All secrets are stored unencrypted in a OS-dependent config directory.
>
> No warranty, backup your keys.

## Usage
```sh
# Add an account
totp-gen new [account-name]
# or:
totp-gen new [account-name] [secret]

# Generate a TOTP code
totp-gen generate [account-name]

# aliases:
totp-gen gen [account-name]
totp-gen g   [account-name]

# Delete an account
totp-gen delete [account-name]
```

## License
[MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE)
