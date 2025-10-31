# TLS-Crypto-KeyExchange

[![PHP Version](https://img.shields.io/badge/php-8.1%2B-blue.svg)](https://www.php.net/releases/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Code Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#)

[English](README.md) | [中文](README.zh-CN.md)

This package provides key exchange algorithm implementations for the TLS protocol, 
supporting various cryptographic key exchange mechanisms required for secure TLS connections.

## Features

- **ECDHE** (Elliptic Curve Diffie-Hellman Ephemeral) - Provides forward secrecy
- **DHE** (Diffie-Hellman Ephemeral) - Classic ephemeral key exchange
- **RSA** - Traditional RSA key exchange
- **PSK** (Pre-Shared Key) - Symmetric key exchange
- **TLS 1.3** - Modern TLS 1.3 key exchange mechanisms
- **X25519/X448** - Modern elliptic curve key exchange

## Requirements

- PHP 8.1 or higher
- OpenSSL extension
- Hash extension

## Installation

```bash
composer require tourze/tls-crypto-keyexchange
```

## Usage

### Basic Key Exchange

```php
use Tourze\TLSCryptoKeyExchange\KeyExchange\KeyExchangeFactory;

// Create an ECDHE key exchange instance
$keyExchange = KeyExchangeFactory::create('ECDHE');

// Generate a key pair
$keyPair = $keyExchange->generateKeyPair();
$privateKey = $keyPair['privateKey'];
$publicKey = $keyPair['publicKey'];

// Compute shared secret (after receiving peer's public key)
$sharedSecret = $keyExchange->computeSharedSecret($privateKey, $peerPublicKey);
```

### Factory Usage

```php
use Tourze\TLSCryptoKeyExchange\KeyExchange\KeyExchangeFactory;

// Create from cipher suite
$keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0x0303);

// Create specific types
$ecdhKeyExchange = KeyExchangeFactory::create('ECDHE');
$dheKeyExchange = KeyExchangeFactory::create('DHE');
$rsaKeyExchange = KeyExchangeFactory::create('RSA');
$pskKeyExchange = KeyExchangeFactory::create('PSK');
$tls13KeyExchange = KeyExchangeFactory::create('TLS13');
```

### Custom Curve Support

```php
use Tourze\TLSCryptoKeyExchange\ECDHE;

$ecdhe = new ECDHE();

// Use a specific curve
$keyPair = $ecdhe->generateKeyPair(['curve' => 'secp384r1']);

// Use custom hash algorithm
$sharedSecret = $ecdhe->computeSharedSecret($privateKey, $peerPublicKey, ['hash' => 'sha384']);
```

## Architecture

The package follows a clean architecture with:

- **Contract Layer**: `KeyExchangeInterface` defines the standard interface
- **Implementation Layer**: Concrete implementations for each key exchange type
- **Factory Pattern**: `KeyExchangeFactory` for creating appropriate instances
- **Exception Handling**: Comprehensive exception hierarchy for different error types

## Exception Handling

The package provides detailed exception types:

- `KeyExchangeException` - Base exception class
- `UnsupportedKeyExchangeException` - Unsupported key exchange type
- `InvalidKeyException` - Invalid key format or content
- `InvalidCurveException` - Invalid elliptic curve
- `InvalidParameterException` - Invalid parameters
- `KeyGenerationException` - Key generation failures

## Security Considerations

- All key exchange implementations provide forward secrecy where applicable
- Proper validation of key parameters and curve compatibility
- Secure random number generation for ephemeral keys
- Protection against timing attacks through consistent error handling

## Testing

Run the test suite:

```bash
./vendor/bin/phpunit packages/tls-crypto-keyexchange/tests
```

## Advanced Usage

### Multiple Key Exchange Types

```php
use Tourze\TLSCryptoKeyExchange\KeyExchange\KeyExchangeFactory;

// Support multiple key exchange mechanisms
$mechanisms = ['ECDHE', 'DHE', 'RSA'];
foreach ($mechanisms as $type) {
    $keyExchange = KeyExchangeFactory::create($type);
    // Perform key exchange operations
}
```

### Error Handling and Validation

```php
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

try {
    $keyPair = $keyExchange->generateKeyPair(['curve' => 'secp256r1']);
    $sharedSecret = $keyExchange->computeSharedSecret(
        $keyPair['privateKey'], 
        $peerPublicKey
    );
} catch (KeyExchangeException $e) {
    // Handle key exchange errors appropriately
    error_log('Key exchange failed: ' . $e->getMessage());
}
```

### Performance Considerations

```php
// For high-performance scenarios, reuse key exchange instances
$keyExchange = KeyExchangeFactory::create('ECDHE');

// Generate multiple key pairs efficiently
for ($i = 0; $i < 1000; $i++) {
    $keyPair = $keyExchange->generateKeyPair();
    // Process key pair
}
```

## Contributing

This package is part of the Tourze TLS implementation suite. 
Please follow the established coding standards and ensure all tests pass.

## License

MIT
