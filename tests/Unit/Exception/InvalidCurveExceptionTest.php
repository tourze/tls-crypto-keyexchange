<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidCurveException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * 无效曲线异常测试
 */
class InvalidCurveExceptionTest extends TestCase
{
    /**
     * 测试异常可以正常实例化
     */
    public function test_canBeInstantiated(): void
    {
        $exception = new InvalidCurveException('Invalid curve');
        
        $this->assertInstanceOf(InvalidCurveException::class, $exception);
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Invalid curve', $exception->getMessage());
    }

    /**
     * 测试异常可以传递错误码
     */
    public function test_canAcceptErrorCode(): void
    {
        $exception = new InvalidCurveException('Invalid curve', 100);
        
        $this->assertEquals('Invalid curve', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
    }

    /**
     * 测试异常可以传递前一个异常
     */
    public function test_canAcceptPreviousException(): void
    {
        $previous = new \Exception('previous error');
        $exception = new InvalidCurveException('Invalid curve', 0, $previous);
        
        $this->assertEquals('Invalid curve', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}