# RFC3394.net
![nuget](https://img.shields.io/nuget/v/RFC3394.net.svg?style=flat)

A simple .NET Standard 2.1 implementation of the RFC3394 AES Key Wrapping Algorithm.

AesCryptoServiceProvider is used internally for cross-platform compatibility.

## Usage
RFC3394.net provides two methods:

- Wrap
- Unwrap

```
RFC3394Algorithm rfc3394 = new RFC3394Algorithm();

byte[] kek = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
byte[] plainKey = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

// wrap a plain text key with a key encryption key (KEK)
byte[] wrappedKey = rfc3394.Wrap(kek, plainKey);

// unwrap a wrapped key with a key encryption key (KEK)
byte[] unwrappedKey = rfc3394.Unwrap(kek, wrappedKey);
```

RFC3394 supports three different key sizes: 128 bits, 192 bits and 256 bits.
Both the KEK and plain text key must adhere to this constraint.

## Performance
This implementation of RFC3394 is on average more than 6 times faster than a similar non .NET Standard implementation.
