<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;
use Tourze\TLSCryptoKeyExchange\X448;

/**
 * X448 密钥交换算法测试
 *
 * @internal
 */
#[CoversClass(X448::class)]
final class X448Test extends TestCase
{
    /**
     * 测试获取算法名称
     */
    public function testGetNameReturnsCorrectName(): void
    {
        $x448 = new X448();
        $this->assertEquals('x448', $x448->getName());
    }

    /**
     * 测试生成密钥对时抛出不支持异常
     */
    public function testGenerateKeyPairThrowsNotSupportedException(): void
    {
        $x448 = new X448();

        $this->expectException(KeyExchangeException::class);
        $this->expectExceptionMessage('当前PHP环境不支持X448密钥交换');

        $x448->generateKeyPair();
    }

    /**
     * 测试计算共享密钥时抛出不支持异常
     */
    public function testComputeSharedSecretThrowsNotSupportedException(): void
    {
        $x448 = new X448();

        $this->expectException(KeyExchangeException::class);
        $this->expectExceptionMessage('当前PHP环境不支持X448密钥交换');

        $x448->computeSharedSecret('dummyPrivateKey', 'dummyPublicKey');
    }
}
