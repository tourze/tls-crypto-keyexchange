<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyGenerationException;

/**
 * 密钥生成异常测试
 *
 * @internal
 */
#[CoversClass(KeyGenerationException::class)]
final class KeyGenerationExceptionTest extends AbstractExceptionTestCase
{
    public function testCanBeCreated(): void
    {
        $exception = new KeyGenerationException('Key generation failed');

        $this->assertInstanceOf(KeyGenerationException::class, $exception);
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Key generation failed', $exception->getMessage());
    }

    public function testCanBeCreatedWithCodeAndPrevious(): void
    {
        $previous = new \Exception('previous error');
        $exception = new KeyGenerationException('Key generation failed', 100, $previous);

        $this->assertEquals('Key generation failed', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testInheritanceHierarchy(): void
    {
        $exception = new KeyGenerationException('Test');

        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }
}
