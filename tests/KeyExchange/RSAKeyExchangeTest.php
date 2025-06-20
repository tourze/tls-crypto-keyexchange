<?php

namespace Tourze\TLSCryptoKeyExchange\Tests\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\KeyExchange\RSAKeyExchange;

/**
 * RSA密钥交换测试
 */
class RSAKeyExchangeTest extends TestCase
{
    /**
     * 测试公钥设置和获取
     */
    public function testSetAndGetServerPublicKey(): void
    {
        $exchange = new RSAKeyExchange();
        $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqUm\ntYTNPYQGQykP0GCc\n1SecN4PXgbgokH+NE5oK3M/hCYV2FfvtgcuaKrWrLzN3IFS\nFKWXm6UZ5AhvBnQQP\nxLKHx3Pu4Q==\n-----END PUBLIC KEY-----";
        
        $exchange->setServerPublicKey($publicKey);
        $this->assertEquals($publicKey, $exchange->getServerPublicKey());
    }
    
    /**
     * 测试生成预主密钥
     */
    public function testGeneratePreMasterSecret(): void
    {
        $exchange = new RSAKeyExchange();
        $version = 0x0303; // TLS 1.2
        
        $preMasterSecret = $exchange->generatePreMasterSecret($version);
        
        // 验证长度为48字节（2字节版本号 + 46字节随机数据）
        $this->assertEquals(48, strlen($preMasterSecret));
        
        // 验证前两个字节是版本号
        $this->assertEquals($version, unpack('n', substr($preMasterSecret, 0, 2))[1]);
    }
    
    /**
     * 测试加密预主密钥
     */
    public function testEncryptPreMasterSecret(): void
    {
        $this->markTestSkipped('跳过需要OpenSSL密钥生成的测试');
    }
    
    /**
     * 测试解密预主密钥
     */
    public function testDecryptPreMasterSecret(): void
    {
        $this->markTestSkipped('跳过需要OpenSSL密钥生成的测试');
    }
    
    /**
     * 测试没有生成预主密钥时加密抛出异常
     */
    public function testEncryptWithoutPreMasterSecretThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Pre-master secret not generated');
        
        $exchange = new RSAKeyExchange();
        $exchange->setServerPublicKey("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqUm\ntYTNPYQGQykP0GCc\n1SecN4PXgbgokH+NE5oK3M/hCYV2FfvtgcuaKrWrLzN3IFS\nFKWXm6UZ5AhvBnQQP\nxLKHx3Pu4Q==\n-----END PUBLIC KEY-----");
        $exchange->encryptPreMasterSecret();
    }
    
    /**
     * 测试没有设置服务器公钥时加密抛出异常
     */
    public function testEncryptWithoutServerPublicKeyThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Server public key not set');
        
        $exchange = new RSAKeyExchange();
        $exchange->generatePreMasterSecret(0x0303);
        $exchange->encryptPreMasterSecret();
    }
} 