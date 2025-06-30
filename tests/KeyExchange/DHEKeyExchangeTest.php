<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\KeyExchange\DHEKeyExchange;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidParameterException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyGenerationException;

/**
 * DHE密钥交换测试
 */
class DHEKeyExchangeTest extends TestCase
{
    private DHEKeyExchange $keyExchange;
    
    protected function setUp(): void
    {
        $this->keyExchange = new DHEKeyExchange();
    }
    
    public function testSetDHParameters(): void
    {
        $p = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF';
        $g = '02';
        $serverPublicKey = 'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5';
        
        $result = $this->keyExchange->setDHParameters($p, $g, $serverPublicKey);
        
        $this->assertSame($this->keyExchange, $result);
        $this->assertEquals($p, $this->keyExchange->getP());
        $this->assertEquals($g, $this->keyExchange->getG());
        $this->assertEquals($serverPublicKey, $this->keyExchange->getServerPublicKey());
    }
    
    public function testGenerateClientKeyPairWithoutParameters(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('DH parameters not set');
        
        $this->keyExchange->generateClientKeyPair();
    }
    
    public function testComputePreMasterSecretWithoutParameters(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('Missing parameters for computing pre-master secret');
        
        $this->keyExchange->computePreMasterSecret();
    }
    
    public function testBinHexConversion(): void
    {
        $keyExchange = new DHEKeyExchange();
        
        // 使用反射访问私有方法
        $reflection = new \ReflectionClass($keyExchange);
        
        $hexToBin = $reflection->getMethod('hexToBin');
        $hexToBin->setAccessible(true);
        
        $binToHex = $reflection->getMethod('binToHex');
        $binToHex->setAccessible(true);
        
        // 测试十六进制转二进制
        $hex = '48656c6c6f'; // "Hello"
        $bin = $hexToBin->invoke($keyExchange, $hex);
        $this->assertEquals('Hello', $bin);
        
        // 测试带 0x 前缀的十六进制
        $hex = '0x48656c6c6f';
        $bin = $hexToBin->invoke($keyExchange, $hex);
        $this->assertEquals('Hello', $bin);
        
        // 测试二进制转十六进制
        $bin = 'Hello';
        $hex = $binToHex->invoke($keyExchange, $bin);
        $this->assertEquals('48656c6c6f', $hex);
    }
}