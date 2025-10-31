<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidCurveException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * 无效曲线异常测试
 *
 * @internal
 */
#[CoversClass(InvalidCurveException::class)]
final class InvalidCurveExceptionTest extends AbstractExceptionTestCase
{
    public function testCanBeCreated(): void
    {
        $exception = new InvalidCurveException('Invalid curve');

        $this->assertInstanceOf(InvalidCurveException::class, $exception);
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Invalid curve', $exception->getMessage());
    }

    public function testCanBeCreatedWithCodeAndPrevious(): void
    {
        $previous = new \Exception('previous error');
        $exception = new InvalidCurveException('Invalid curve', 100, $previous);

        $this->assertEquals('Invalid curve', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testInheritanceHierarchy(): void
    {
        $exception = new InvalidCurveException('Test');

        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }
}
