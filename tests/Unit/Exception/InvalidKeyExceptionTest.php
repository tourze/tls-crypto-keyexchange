<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidKeyException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * 无效密钥异常测试
 */
class InvalidKeyExceptionTest extends TestCase
{
    /**
     * 测试异常可以正常实例化
     */
    public function test_canBeInstantiated(): void
    {
        $exception = new InvalidKeyException('Invalid key');
        
        $this->assertInstanceOf(InvalidKeyException::class, $exception);
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Invalid key', $exception->getMessage());
    }

    /**
     * 测试异常可以传递错误码
     */
    public function test_canAcceptErrorCode(): void
    {
        $exception = new InvalidKeyException('Invalid key', 100);
        
        $this->assertEquals('Invalid key', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
    }

    /**
     * 测试异常可以传递前一个异常
     */
    public function test_canAcceptPreviousException(): void
    {
        $previous = new \Exception('previous error');
        $exception = new InvalidKeyException('Invalid key', 0, $previous);
        
        $this->assertEquals('Invalid key', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}