<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidParameterException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * 无效参数异常测试
 */
class InvalidParameterExceptionTest extends TestCase
{
    /**
     * 测试异常可以正常实例化
     */
    public function test_canBeInstantiated(): void
    {
        $exception = new InvalidParameterException('Invalid parameter');
        
        $this->assertInstanceOf(InvalidParameterException::class, $exception);
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Invalid parameter', $exception->getMessage());
    }

    /**
     * 测试异常可以传递错误码
     */
    public function test_canAcceptErrorCode(): void
    {
        $exception = new InvalidParameterException('Invalid parameter', 100);
        
        $this->assertEquals('Invalid parameter', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
    }

    /**
     * 测试异常可以传递前一个异常
     */
    public function test_canAcceptPreviousException(): void
    {
        $previous = new \Exception('previous error');
        $exception = new InvalidParameterException('Invalid parameter', 0, $previous);
        
        $this->assertEquals('Invalid parameter', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}