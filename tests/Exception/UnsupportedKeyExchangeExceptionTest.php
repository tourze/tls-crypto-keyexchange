<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;
use Tourze\TLSCryptoKeyExchange\Exception\UnsupportedKeyExchangeException;

/**
 * 不支持的密钥交换类型异常测试
 *
 * @internal
 */
#[CoversClass(UnsupportedKeyExchangeException::class)]
final class UnsupportedKeyExchangeExceptionTest extends AbstractExceptionTestCase
{
    public function testCanBeCreated(): void
    {
        $exception = new UnsupportedKeyExchangeException('Unsupported key exchange');

        $this->assertInstanceOf(UnsupportedKeyExchangeException::class, $exception);
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Unsupported key exchange', $exception->getMessage());
    }

    public function testCanBeCreatedWithCodeAndPrevious(): void
    {
        $previous = new \Exception('previous error');
        $exception = new UnsupportedKeyExchangeException('Unsupported key exchange', 100, $previous);

        $this->assertEquals('Unsupported key exchange', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testInheritanceHierarchy(): void
    {
        $exception = new UnsupportedKeyExchangeException('Test');

        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }
}
