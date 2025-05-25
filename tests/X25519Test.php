<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests;

use ParagonIE_Sodium_Compat;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;
use Tourze\TLSCryptoKeyExchange\X25519;

/**
 * X25519 密钥交换算法测试
 */
class X25519Test extends TestCase
{
    /**
     * 测试获取算法名称
     */
    public function test_getName_returnsCorrectName(): void
    {
        $x25519 = new X25519();
        $this->assertEquals('x25519', $x25519->getName());
    }

    /**
     * 测试生成密钥对
     */
    public function test_generateKeyPair_returnsValidKeyPair(): void
    {
        $x25519 = new X25519();
        $keyPair = $x25519->generateKeyPair();

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);

        $this->assertNotEmpty($keyPair['privateKey']);
        $this->assertNotEmpty($keyPair['publicKey']);

        // 验证密钥长度
        $this->assertEquals(ParagonIE_Sodium_Compat::CRYPTO_BOX_SECRETKEYBYTES, strlen($keyPair['privateKey']));
        $this->assertEquals(ParagonIE_Sodium_Compat::CRYPTO_BOX_PUBLICKEYBYTES, strlen($keyPair['publicKey']));
    }

    /**
     * 测试计算共享密钥
     */
    public function test_computeSharedSecret_withValidKeys_returnsValidSecret(): void
    {
        $x25519 = new X25519();
        
        // 生成 Alice 的密钥对
        $aliceKeyPair = $x25519->generateKeyPair();
        
        // 生成 Bob 的密钥对
        $bobKeyPair = $x25519->generateKeyPair();
        
        // Alice 计算共享密钥
        $aliceSharedSecret = $x25519->computeSharedSecret(
            $aliceKeyPair['privateKey'],
            $bobKeyPair['publicKey']
        );
        
        // Bob 计算共享密钥
        $bobSharedSecret = $x25519->computeSharedSecret(
            $bobKeyPair['privateKey'],
            $aliceKeyPair['publicKey']
        );
        
        // 验证 Alice 和 Bob 计算的共享密钥相同
        $this->assertEquals($aliceSharedSecret, $bobSharedSecret);
        $this->assertNotEmpty($aliceSharedSecret);

        // 验证共享密钥长度
        $this->assertEquals(ParagonIE_Sodium_Compat::CRYPTO_SCALARMULT_BYTES, strlen($aliceSharedSecret));
    }

    /**
     * 测试使用无效私钥长度时抛出异常
     */
    public function test_computeSharedSecret_withInvalidPrivateKeyLength_throwsException(): void
    {
        $x25519 = new X25519();
        $keyPair = $x25519->generateKeyPair();
        
        $this->expectException(KeyExchangeException::class);
        $x25519->computeSharedSecret(
            substr($keyPair['privateKey'], 0, ParagonIE_Sodium_Compat::CRYPTO_BOX_SECRETKEYBYTES - 1), // 截断一个字节
            $keyPair['publicKey']
        );
    }

    /**
     * 测试使用无效公钥长度时抛出异常
     */
    public function test_computeSharedSecret_withInvalidPublicKeyLength_throwsException(): void
    {
        $x25519 = new X25519();
        $keyPair = $x25519->generateKeyPair();
        
        $this->expectException(KeyExchangeException::class);
        $x25519->computeSharedSecret(
            $keyPair['privateKey'],
            substr($keyPair['publicKey'], 0, ParagonIE_Sodium_Compat::CRYPTO_BOX_PUBLICKEYBYTES - 1) // 截断一个字节
        );
    }

    /**
     * 测试不同私钥和公钥生成不同的共享密钥
     */
    public function test_differentKeyPairs_generateDifferentSharedSecrets(): void
    {
        $x25519 = new X25519();
        
        // 生成三对密钥对
        $keyPair1 = $x25519->generateKeyPair();
        $keyPair2 = $x25519->generateKeyPair();
        $keyPair3 = $x25519->generateKeyPair();
        
        // 计算不同组合的共享密钥
        $sharedSecret12 = $x25519->computeSharedSecret($keyPair1['privateKey'], $keyPair2['publicKey']);
        $sharedSecret13 = $x25519->computeSharedSecret($keyPair1['privateKey'], $keyPair3['publicKey']);
        $sharedSecret23 = $x25519->computeSharedSecret($keyPair2['privateKey'], $keyPair3['publicKey']);
        
        // 验证不同组合生成的共享密钥不同
        $this->assertNotEquals($sharedSecret12, $sharedSecret13);
        $this->assertNotEquals($sharedSecret12, $sharedSecret23);
        $this->assertNotEquals($sharedSecret13, $sharedSecret23);
    }
} 