<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\ECDHE;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * ECDHE 密钥交换算法测试
 */
class ECDHETest extends TestCase
{
    /**
     * 测试获取算法名称
     */
    public function test_getName_returnsCorrectName(): void
    {
        $ecdhe = new ECDHE();
        $this->assertEquals('ecdhe', $ecdhe->getName());
    }

    /**
     * 测试使用默认参数生成密钥对
     */
    public function test_generateKeyPair_withDefaultParams_returnsValidKeyPair(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $ecdhe = new ECDHE();
        $keyPair = $ecdhe->generateKeyPair();

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertArrayHasKey('curve', $keyPair);

        $this->assertNotEmpty($keyPair['privateKey']);
        $this->assertNotEmpty($keyPair['publicKey']);
        $this->assertEquals('prime256v1', $keyPair['curve']);
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair['privateKey']);
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair['publicKey']);
    }

    /**
     * 测试使用自定义曲线参数生成密钥对
     */
    public function test_generateKeyPair_withCustomCurve_returnsValidKeyPair(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $curves = openssl_get_curve_names();
        if (!$curves || !in_array('secp384r1', $curves)) {
            $this->markTestSkipped('当前 OpenSSL 环境不支持 secp384r1 曲线');
        }

        $ecdhe = new ECDHE();
        $keyPair = $ecdhe->generateKeyPair(['curve' => 'secp384r1']);

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertArrayHasKey('curve', $keyPair);
        $this->assertEquals('secp384r1', $keyPair['curve']);
    }

    /**
     * 测试使用不支持的曲线参数时抛出异常
     */
    public function test_generateKeyPair_withUnsupportedCurve_throwsException(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        $ecdhe = new ECDHE();
        
        $this->expectException(KeyExchangeException::class);
        $ecdhe->generateKeyPair(['curve' => 'unsupported_curve_name']);
    }

    /**
     * 测试计算共享密钥
     */
    public function test_computeSharedSecret_withValidKeys_returnsValidSecret(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        // PHP 8 以下版本可能不支持 openssl_pkey_derive 函数
        if (version_compare(PHP_VERSION, '8.0.0', '<') && !function_exists('openssl_pkey_derive')) {
            $this->markTestSkipped('当前 PHP 版本不支持 ECDHE 点乘法操作（缺少 openssl_pkey_derive 函数）');
        }

        $ecdhe = new ECDHE();
        
        // 生成 Alice 的密钥对
        $aliceKeyPair = $ecdhe->generateKeyPair();
        
        // 生成 Bob 的密钥对，使用相同的曲线
        $bobKeyPair = $ecdhe->generateKeyPair(['curve' => $aliceKeyPair['curve']]);
        
        // Alice 计算共享密钥
        $aliceSharedSecret = $ecdhe->computeSharedSecret(
            $aliceKeyPair['privateKey'],
            $bobKeyPair['publicKey']
        );
        
        // Bob 计算共享密钥
        $bobSharedSecret = $ecdhe->computeSharedSecret(
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

        // PHP 8 以下版本可能不支持 openssl_pkey_derive 函数
        if (version_compare(PHP_VERSION, '8.0.0', '<') && !function_exists('openssl_pkey_derive')) {
            $this->markTestSkipped('当前 PHP 版本不支持 ECDHE 点乘法操作（缺少 openssl_pkey_derive 函数）');
        }

        $ecdhe = new ECDHE();
        $keyPair = $ecdhe->generateKeyPair();
        
        $this->expectException(KeyExchangeException::class);
        $ecdhe->computeSharedSecret(
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

        // PHP 8 以下版本可能不支持 openssl_pkey_derive 函数
        if (version_compare(PHP_VERSION, '8.0.0', '<') && !function_exists('openssl_pkey_derive')) {
            $this->markTestSkipped('当前 PHP 版本不支持 ECDHE 点乘法操作（缺少 openssl_pkey_derive 函数）');
        }

        $ecdhe = new ECDHE();
        $keyPair = $ecdhe->generateKeyPair();
        
        $this->expectException(KeyExchangeException::class);
        $ecdhe->computeSharedSecret(
            $keyPair['privateKey'],
            'invalid-public-key'
        );
    }

    /**
     * 测试使用不匹配的曲线参数时抛出异常
     */
    public function test_computeSharedSecret_withMismatchedCurves_throwsException(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL 扩展未加载，跳过测试');
        }

        // PHP 8 以下版本可能不支持 openssl_pkey_derive 函数
        if (version_compare(PHP_VERSION, '8.0.0', '<') && !function_exists('openssl_pkey_derive')) {
            $this->markTestSkipped('当前 PHP 版本不支持 ECDHE 点乘法操作（缺少 openssl_pkey_derive 函数）');
        }

        $curves = openssl_get_curve_names();
        if (!$curves || !in_array('secp384r1', $curves) || !in_array('prime256v1', $curves)) {
            $this->markTestSkipped('当前 OpenSSL 环境不支持所需曲线');
        }

        $ecdhe = new ECDHE();
        
        // 使用 P-256 曲线生成密钥对
        $p256KeyPair = $ecdhe->generateKeyPair(['curve' => 'prime256v1']);
        
        // 使用 P-384 曲线生成密钥对
        $p384KeyPair = $ecdhe->generateKeyPair(['curve' => 'secp384r1']);
        
        // 不同曲线的密钥尝试计算共享密钥，应该抛出异常
        $this->expectException(KeyExchangeException::class);
        $ecdhe->computeSharedSecret(
            $p256KeyPair['privateKey'],
            $p384KeyPair['publicKey']
        );
    }
} 