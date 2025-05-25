<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoFactory\CryptoFactory;
use Tourze\TLSCryptoFactory\Exception\CryptoException;
use Tourze\TLSCryptoKeyExchange\Contract\KeyExchangeInterface;
use Tourze\TLSCryptoKeyExchange\DHE;
use Tourze\TLSCryptoKeyExchange\ECDHE;
use Tourze\TLSCryptoKeyExchange\X25519;
use Tourze\TLSCryptoKeyExchange\X448;

/**
 * 测试 CryptoFactory 与密钥交换算法的集成
 */
class CryptoFactoryTest extends TestCase
{
    /**
     * 测试 CryptoFactory 创建 DHE 密钥交换算法
     */
    public function test_createKeyExchange_DHEAlgorithm_returnsDHEInstance(): void
    {
        $keyExchange = CryptoFactory::createKeyExchange('dhe');
        
        $this->assertInstanceOf(KeyExchangeInterface::class, $keyExchange);
        $this->assertInstanceOf(DHE::class, $keyExchange);
        $this->assertEquals('dhe', $keyExchange->getName());
    }
    
    /**
     * 测试 CryptoFactory 创建 ECDHE 密钥交换算法
     */
    public function test_createKeyExchange_ECDHEAlgorithm_returnsECDHEInstance(): void
    {
        $keyExchange = CryptoFactory::createKeyExchange('ecdhe');
        
        $this->assertInstanceOf(KeyExchangeInterface::class, $keyExchange);
        $this->assertInstanceOf(ECDHE::class, $keyExchange);
        $this->assertEquals('ecdhe', $keyExchange->getName());
    }
    
    /**
     * 测试 CryptoFactory 创建 X25519 密钥交换算法
     */
    public function test_createKeyExchange_X25519Algorithm_returnsX25519Instance(): void
    {
        $keyExchange = CryptoFactory::createKeyExchange('x25519');
        
        $this->assertInstanceOf(KeyExchangeInterface::class, $keyExchange);
        $this->assertInstanceOf(X25519::class, $keyExchange);
        $this->assertEquals('x25519', $keyExchange->getName());
    }
    
    /**
     * 测试 CryptoFactory 创建 X448 密钥交换算法
     */
    public function test_createKeyExchange_X448Algorithm_returnsX448Instance(): void
    {
        $keyExchange = CryptoFactory::createKeyExchange('x448');
        
        $this->assertInstanceOf(KeyExchangeInterface::class, $keyExchange);
        $this->assertInstanceOf(X448::class, $keyExchange);
        $this->assertEquals('x448', $keyExchange->getName());
    }
    
    /**
     * 测试 CryptoFactory 创建不支持的密钥交换算法时抛出异常
     */
    public function test_createKeyExchange_unsupportedAlgorithm_throwsException(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('不支持的密钥交换算法');
        
        CryptoFactory::createKeyExchange('unsupported_algorithm');
    }
}
