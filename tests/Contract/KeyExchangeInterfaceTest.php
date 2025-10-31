<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Contract;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Contract\KeyExchangeInterface;

/**
 * 测试密钥交换接口实现的一致性
 *
 * @internal
 */
#[CoversClass(KeyExchangeInterface::class)]
final class KeyExchangeInterfaceTest extends TestCase
{
    /**
     * 创建一个模拟的 KeyExchangeInterface 实现
     */
    private function createMockKeyExchange(string $name): KeyExchangeInterface
    {
        return new class($name) implements KeyExchangeInterface {
            public function __construct(private string $name)
            {
            }

            public function getName(): string
            {
                return $this->name;
            }

            public function generateKeyPair(array $options = []): array
            {
                return [
                    'privateKey' => 'mock_private_key',
                    'publicKey' => 'mock_public_key',
                ];
            }

            public function computeSharedSecret(string $privateKey, string $publicKey, array $options = []): string
            {
                return 'mock_shared_secret';
            }
        };
    }

    /**
     * 测试接口 getName 方法
     */
    public function testGetName(): void
    {
        $keyExchange = $this->createMockKeyExchange('test_algorithm');
        $this->assertEquals('test_algorithm', $keyExchange->getName());
    }

    /**
     * 测试接口 generateKeyPair 方法
     */
    public function testGenerateKeyPair(): void
    {
        $keyExchange = $this->createMockKeyExchange('test_algorithm');
        $keyPair = $keyExchange->generateKeyPair();

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertNotEmpty($keyPair['privateKey']);
        $this->assertNotEmpty($keyPair['publicKey']);
    }

    /**
     * 测试接口 computeSharedSecret 方法
     */
    public function testComputeSharedSecret(): void
    {
        $keyExchange = $this->createMockKeyExchange('test_algorithm');
        $sharedSecret = $keyExchange->computeSharedSecret('private_key', 'public_key');

        $this->assertNotEmpty($sharedSecret);
        $this->assertEquals('mock_shared_secret', $sharedSecret);
    }
}
