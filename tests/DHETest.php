<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\DHE;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * DHE 密钥交换算法测试
 */
class DHETest extends TestCase
{
    /**
     * 测试获取算法名称
     */
    public function test_getName_returnsCorrectName(): void
    {
        $dhe = new DHE();
        $this->assertEquals('dhe', $dhe->getName());
    }

    /**
     * 测试使用默认参数生成密钥对
     */
    public function test_generateKeyPair_withDefaultParams_returnsValidKeyPair(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair();

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertArrayHasKey('params', $keyPair);
        $this->assertArrayHasKey('group', $keyPair);
        $this->assertArrayHasKey('bits', $keyPair);

        $this->assertNotEmpty($keyPair['privateKey']);
        $this->assertNotEmpty($keyPair['publicKey']);
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair['privateKey']);
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair['publicKey']);
    }

    /**
     * 测试使用自定义组参数生成密钥对
     */
    public function test_generateKeyPair_withCustomGroup_returnsValidKeyPair(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair(['group' => 'ffdhe3072']);

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertArrayHasKey('params', $keyPair);
        $this->assertEquals('ffdhe3072', $keyPair['group']);
        $this->assertEquals(3072, $keyPair['bits']);
    }

    /**
     * 测试使用无效组参数时，会回退到默认参数
     */
    public function test_generateKeyPair_withInvalidGroup_fallsBackToDefaultGroup(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair(['group' => 'invalid_group_name']);

        $this->assertArrayHasKey('group', $keyPair);
        $this->assertEquals('ffdhe2048', $keyPair['group']);
        $this->assertEquals(2048, $keyPair['bits']);
    }

    /**
     * 测试计算共享密钥
     */
    public function test_computeSharedSecret_withValidKeys_returnsValidSecret(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $dhe = new DHE();
        
        // 生成 Alice 的密钥对
        $aliceKeyPair = $dhe->generateKeyPair();
        
        // 生成 Bob 的密钥对，使用相同的组
        $bobKeyPair = $dhe->generateKeyPair(['group' => $aliceKeyPair['group']]);
        
        // Alice 计算共享密钥
        $aliceSharedSecret = $dhe->computeSharedSecret(
            $aliceKeyPair['privateKey'],
            $bobKeyPair['publicKey']
        );
        
        // Bob 计算共享密钥
        $bobSharedSecret = $dhe->computeSharedSecret(
            $bobKeyPair['privateKey'],
            $aliceKeyPair['publicKey']
        );
        
        // 验证 Alice 和 Bob 计算的共享密钥相同
        $this->assertEquals($aliceSharedSecret, $bobSharedSecret);
        $this->assertNotEmpty($aliceSharedSecret);
    }

    /**
     * 测试使用无效私钥时抛出异常
     */
    public function test_computeSharedSecret_withInvalidPrivateKey_throwsException(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair();
        
        $this->expectException(KeyExchangeException::class);
        $dhe->computeSharedSecret(
            'invalid-private-key',
            $keyPair['publicKey']
        );
    }

    /**
     * 测试使用无效公钥时抛出异常
     */
    public function test_computeSharedSecret_withInvalidPublicKey_throwsException(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $dhe = new DHE();
        $keyPair = $dhe->generateKeyPair();
        
        $this->expectException(KeyExchangeException::class);
        $dhe->computeSharedSecret(
            $keyPair['privateKey'],
            'invalid-public-key'
        );
    }
} 