<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * 密钥交换异常测试
 */
class KeyExchangeExceptionTest extends TestCase
{
    /**
     * 测试异常可以正常实例化
     */
    public function test_canBeInstantiated(): void
    {
        $exception = new KeyExchangeException('test message');
        
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('test message', $exception->getMessage());
    }

    /**
     * 测试异常可以传递错误码
     */
    public function test_canAcceptErrorCode(): void
    {
        $exception = new KeyExchangeException('test message', 100);
        
        $this->assertEquals('test message', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
    }

    /**
     * 测试异常可以传递前一个异常
     */
    public function test_canAcceptPreviousException(): void
    {
        $previous = new \Exception('previous error');
        $exception = new KeyExchangeException('test message', 0, $previous);
        
        $this->assertEquals('test message', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}