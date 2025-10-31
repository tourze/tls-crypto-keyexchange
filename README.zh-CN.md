# tls-crypto-keyexchange

[![PHP Version](https://img.shields.io/badge/php-8.1%2B-blue.svg)](https://www.php.net/releases/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Code Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#)

[English](README.md) | [中文](README.zh-CN.md)

此包为TLS协议提供密钥交换算法实现，支持安全TLS连接所需的各种密码学密钥交换机制。

## 特性

- **ECDHE** (椭圆曲线Diffie-Hellman临时密钥) - 提供前向保密性
- **DHE** (Diffie-Hellman临时密钥) - 经典临时密钥交换
- **RSA** - 传统RSA密钥交换
- **PSK** (预共享密钥) - 对称密钥交换
- **TLS 1.3** - 现代TLS 1.3密钥交换机制
- **X25519/X448** - 现代椭圆曲线密钥交换

## 系统要求

- PHP 8.1 或更高版本
- OpenSSL扩展
- Hash扩展

## 安装

```bash
composer require tourze/tls-crypto-keyexchange
```

## 使用方法

### 基本密钥交换

```php
use Tourze\TLSCryptoKeyExchange\KeyExchange\KeyExchangeFactory;

// 创建ECDHE密钥交换实例
$keyExchange = KeyExchangeFactory::create('ECDHE');

// 生成密钥对
$keyPair = $keyExchange->generateKeyPair();
$privateKey = $keyPair['privateKey'];
$publicKey = $keyPair['publicKey'];

// 计算共享密钥（收到对端公钥后）
$sharedSecret = $keyExchange->computeSharedSecret($privateKey, $peerPublicKey);
```

### 工厂模式使用

```php
use Tourze\TLSCryptoKeyExchange\KeyExchange\KeyExchangeFactory;

// 根据密码套件创建
$keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0x0303);

// 创建特定类型
$ecdhKeyExchange = KeyExchangeFactory::create('ECDHE');
$dheKeyExchange = KeyExchangeFactory::create('DHE');
$rsaKeyExchange = KeyExchangeFactory::create('RSA');
$pskKeyExchange = KeyExchangeFactory::create('PSK');
$tls13KeyExchange = KeyExchangeFactory::create('TLS13');
```

### 自定义曲线支持

```php
use Tourze\TLSCryptoKeyExchange\ECDHE;

$ecdhe = new ECDHE();

// 使用特定椭圆曲线
$keyPair = $ecdhe->generateKeyPair(['curve' => 'secp384r1']);

// 使用自定义哈希算法
$sharedSecret = $ecdhe->computeSharedSecret($privateKey, $peerPublicKey, ['hash' => 'sha384']);
```

## 架构设计

该包遵循清晰的架构设计：

- **合约层**: `KeyExchangeInterface` 定义标准接口
- **实现层**: 每种密钥交换类型的具体实现
- **工厂模式**: `KeyExchangeFactory` 创建适当的实例
- **异常处理**: 针对不同错误类型的完整异常层次结构

## 异常处理

该包提供详细的异常类型：

- `KeyExchangeException` - 基础异常类
- `UnsupportedKeyExchangeException` - 不支持的密钥交换类型
- `InvalidKeyException` - 无效的密钥格式或内容
- `InvalidCurveException` - 无效的椭圆曲线
- `InvalidParameterException` - 无效的参数
- `KeyGenerationException` - 密钥生成失败

## 安全考虑

- 所有密钥交换实现在适用情况下都提供前向保密性
- 对密钥参数和曲线兼容性进行适当验证
- 为临时密钥提供安全的随机数生成
- 通过一致的错误处理防止时序攻击

## 测试

运行测试套件：

```bash
./vendor/bin/phpunit packages/tls-crypto-keyexchange/tests
```

## 高级用法

### 多种密钥交换类型

```php
use Tourze\TLSCryptoKeyExchange\KeyExchange\KeyExchangeFactory;

// 支持多种密钥交换机制
$mechanisms = ['ECDHE', 'DHE', 'RSA'];
foreach ($mechanisms as $type) {
    $keyExchange = KeyExchangeFactory::create($type);
    // 执行密钥交换操作
}
```

### 错误处理和验证

```php
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

try {
    $keyPair = $keyExchange->generateKeyPair(['curve' => 'secp256r1']);
    $sharedSecret = $keyExchange->computeSharedSecret(
        $keyPair['privateKey'], 
        $peerPublicKey
    );
} catch (KeyExchangeException $e) {
    // 适当处理密钥交换错误
    error_log('密钥交换失败: ' . $e->getMessage());
}
```

### 性能考虑

```php
// 对于高性能场景，重用密钥交换实例
$keyExchange = KeyExchangeFactory::create('ECDHE');

// 高效生成多个密钥对
for ($i = 0; $i < 1000; $i++) {
    $keyPair = $keyExchange->generateKeyPair();
    // 处理密钥对
}
```

## 贡献

此包是Tourze TLS实现套件的一部分。请遵循既定的编码标准并确保所有测试通过。

## 许可证

MIT
