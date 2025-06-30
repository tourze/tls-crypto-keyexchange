<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\UnsupportedKeyExchangeException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * 不支持的密钥交换类型异常测试
 */
class UnsupportedKeyExchangeExceptionTest extends TestCase
{
    /**
     * 测试异常可以正常实例化
     */
    public function test_canBeInstantiated(): void
    {
        $exception = new UnsupportedKeyExchangeException('Unsupported key exchange');
        
        $this->assertInstanceOf(UnsupportedKeyExchangeException::class, $exception);
        $this->assertInstanceOf(KeyExchangeException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Unsupported key exchange', $exception->getMessage());
    }

    /**
     * 测试异常可以传递错误码
     */
    public function test_canAcceptErrorCode(): void
    {
        $exception = new UnsupportedKeyExchangeException('Unsupported key exchange', 100);
        
        $this->assertEquals('Unsupported key exchange', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
    }

    /**
     * 测试异常可以传递前一个异常
     */
    public function test_canAcceptPreviousException(): void
    {
        $previous = new \Exception('previous error');
        $exception = new UnsupportedKeyExchangeException('Unsupported key exchange', 0, $previous);
        
        $this->assertEquals('Unsupported key exchange', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
    }
}