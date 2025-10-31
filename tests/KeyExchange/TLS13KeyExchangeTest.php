<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\KeyExchange;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidCurveException;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidParameterException;
use Tourze\TLSCryptoKeyExchange\KeyExchange\TLS13KeyExchange;

/**
 * TLS 1.3密钥交换测试
 *
 * @internal
 */
#[CoversClass(TLS13KeyExchange::class)]
final class TLS13KeyExchangeTest extends TestCase
{
    private TLS13KeyExchange $keyExchange;

    protected function setUp(): void
    {
        parent::setUp();

        $this->keyExchange = new TLS13KeyExchange();
    }

    public function testSetKeyShareParametersWithValidGroup(): void
    {
        $group = 'x25519';
        $serverKeyShare = base64_encode(random_bytes(32));

        $this->keyExchange->setKeyShareParameters($group, $serverKeyShare);
        $this->assertEquals($group, $this->keyExchange->getGroup());
        $this->assertEquals($serverKeyShare, $this->keyExchange->getServerKeyShare());
    }

    public function testSetKeyShareParametersWithInvalidGroup(): void
    {
        $this->expectException(InvalidCurveException::class);
        $this->expectExceptionMessage('Unsupported key share group: invalid_group');

        $this->keyExchange->setKeyShareParameters('invalid_group', 'dummy_key');
    }

    public function testGenerateKeyShareWithoutGroup(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('Key share group not set');

        $this->keyExchange->generateKeyShare();
    }

    public function testComputeSharedSecretWithoutParameters(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('Missing parameters for computing shared secret');

        $this->keyExchange->computeSharedSecret();
    }

    public function testFormatKeyShareExtensionWithoutKeyShare(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('Client key share not generated');

        $this->keyExchange->formatKeyShareExtension();
    }

    public function testSupportedGroups(): void
    {
        $supportedGroups = ['x25519', 'x448', 'secp256r1', 'secp384r1', 'secp521r1'];

        foreach ($supportedGroups as $group) {
            $keyExchange = new TLS13KeyExchange();
            $keyExchange->setKeyShareParameters($group, 'dummy_key');
            $this->assertEquals($group, $keyExchange->getGroup());
        }
    }

    public function testGetGroupId(): void
    {
        $keyExchange = new TLS13KeyExchange();

        // 使用反射访问私有方法
        $reflection = new \ReflectionClass($keyExchange);
        $getGroupId = $reflection->getMethod('getGroupId');
        $getGroupId->setAccessible(true);

        // 测试已知的组ID
        $groupIds = [
            'secp256r1' => 23,
            'secp384r1' => 24,
            'secp521r1' => 25,
            'x25519' => 29,
            'x448' => 30,
        ];

        foreach ($groupIds as $group => $expectedId) {
            $id = $getGroupId->invoke($keyExchange, $group);
            $this->assertEquals($expectedId, $id);
        }

        // 测试未知组
        $this->expectException(InvalidCurveException::class);
        $this->expectExceptionMessage('Unknown group: unknown_group');
        $getGroupId->invoke($keyExchange, 'unknown_group');
    }
}
