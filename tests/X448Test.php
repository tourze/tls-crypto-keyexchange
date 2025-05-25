<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;
use Tourze\TLSCryptoKeyExchange\X448;

/**
 * X448 密钥交换算法测试
 */
class X448Test extends TestCase
{
    /**
     * 测试获取算法名称
     */
    public function test_getName_returnsCorrectName(): void
    {
        $x448 = new X448();
        $this->assertEquals('x448', $x448->getName());
    }

    /**
     * 测试生成密钥对时抛出不支持异常
     */
    public function test_generateKeyPair_throwsNotSupportedException(): void
    {
        $x448 = new X448();
        
        $this->expectException(KeyExchangeException::class);
        $this->expectExceptionMessage('当前PHP环境不支持X448密钥交换');
        
        $x448->generateKeyPair();
    }

    /**
     * 测试计算共享密钥时抛出不支持异常
     */
    public function test_computeSharedSecret_throwsNotSupportedException(): void
    {
        $x448 = new X448();
        
        $this->expectException(KeyExchangeException::class);
        $this->expectExceptionMessage('当前PHP环境不支持X448密钥交换');
        
        $x448->computeSharedSecret('dummyPrivateKey', 'dummyPublicKey');
    }

    /**
     * 当 libsodium 支持 X448 时，此测试将需要更新
     */
    public function test_futureSupport_skippedForNow(): void
    {
        $this->markTestSkipped('这个测试将在 libsodium 支持 X448 密钥交换后实现');
        
        // 未来实现的代码示例
        /*
        $x448 = new X448();
        
        // 生成 Alice 的密钥对
        $aliceKeyPair = $x448->generateKeyPair();
        
        // 生成 Bob 的密钥对
        $bobKeyPair = $x448->generateKeyPair();
        
        // Alice 计算共享密钥
        $aliceSharedSecret = $x448->computeSharedSecret(
            $aliceKeyPair['privateKey'],
            $bobKeyPair['publicKey']
        );
        
        // Bob 计算共享密钥
        $bobSharedSecret = $x448->computeSharedSecret(
            $bobKeyPair['privateKey'],
            $aliceKeyPair['publicKey']
        );
        
        // 验证 Alice 和 Bob 计算的共享密钥相同
        $this->assertEquals($aliceSharedSecret, $bobSharedSecret);
        */
    }
} 