<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCryptoKeyExchange\Exception\GenericKeyExchangeException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * 通用密钥交换异常测试
 *
 * @internal
 */
#[CoversClass(GenericKeyExchangeException::class)]
final class GenericKeyExchangeExceptionTest extends AbstractExceptionTestCase
{
    public function testCanBeCreated(): void
    {
        $exception = new GenericKeyExchangeException('test message');

        $this->assertInstanceOf(GenericKeyExchangeException::class, $exception);
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('test message', $exception->getMessage());
    }

    public function testCanBeCreatedWithCodeAndPrevious(): void
    {
        $previous = new \Exception('previous error');
        $exception = new GenericKeyExchangeException('test message', 100, $previous);

        $this->assertEquals('test message', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testInheritanceHierarchy(): void
    {
        $exception = new GenericKeyExchangeException('Test');

        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }
}
