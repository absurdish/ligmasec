# LigmaSec

Light-weight, lattice-based post-quantum cryptographic library, designed to resist against attacks from both classical and quantum computers.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
ligmasec = "0.1.0"
```

or simply

```sh
cargo add ligmasec
```

### Basic Example

```rust
use ligmasec::{LigmaSafety, SecurityLevel};

fn main() {
    // create a new instance with Standard security level
    let ligma = LigmaSafety::with_security_level(SecurityLevel::Standard);

    // generate keypair
    let (public_key, private_key) = ligma.generate_keypair().unwrap();

    // sign a message
    let message = b"hello, ligma balls!";
    let signature = ligma.sign(message, &private_key).unwrap();

    // verify the signature
    let is_valid = ligma.verify(message, &signature, &public_key).unwrap();
    assert!(is_valid);
}
```

## Security Parameters

Security levels come with pre-configured parameters:

| Level    | Lattice Dimension | Modulus  |
|----------|------------------|-----------|
| Basic    | 512             | 8,380,417 |
| Standard | 768             | 16,760,833|
| Paranoid | 1024            | 33,554,393|

But dimensions can be increased for better security

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Safety Notice

This implementation is for educational and research purposes. While designed with security in mind, it has not undergone formal cryptographic review. Use in production systems at your own risk.
