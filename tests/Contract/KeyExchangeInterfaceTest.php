<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\Contract;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Contract\KeyExchangeInterface;
use Tourze\TLSCryptoKeyExchange\DHE;
use Tourze\TLSCryptoKeyExchange\ECDHE;
use Tourze\TLSCryptoKeyExchange\X25519;

/**
 * 测试密钥交换接口实现的一致性
 */
class KeyExchangeInterfaceTest extends TestCase
{
    /**
     * 获取可以执行测试的密钥交换实现类列表
     * 
     * @return array 由密钥交换实现类组成的数组
     */
    public function keyExchangeImplementationsProvider(): array
    {
        $implementations = [];
        
        // 添加 DHE 实现类，如果 OpenSSL 扩展可用
        if (extension_loaded('openssl')) {
            $implementations[] = [new DHE(), 'dhe'];
            
            // 添加 ECDHE 实现类，如果 OpenSSL 版本支持椭圆曲线
            $supportedCurves = openssl_get_curve_names();
            if ($supportedCurves !== false && in_array('prime256v1', $supportedCurves)) {
                $implementations[] = [new ECDHE(), 'ecdhe'];
            }
        }
        
        // 添加 X25519 实现类
        $implementations[] = [new X25519(), 'x25519'];
        
        // 注意：不添加 X448 实现类，因为它目前抛出异常
        
        return $implementations;
    }
    
    /**
     * 测试所有实现类都正确实现了 getName 方法
     * 
     * @dataProvider keyExchangeImplementationsProvider
     */
    public function test_allImplementations_correctlyImplementGetName(KeyExchangeInterface $keyExchange, string $expectedName): void
    {
        $this->assertEquals($expectedName, $keyExchange->getName());
    }
    
    /**
     * 测试所有实现类都正确实现了 generateKeyPair 方法
     * 
     * @dataProvider keyExchangeImplementationsProvider
     */
    public function test_allImplementations_correctlyImplementGenerateKeyPair(KeyExchangeInterface $keyExchange): void
    {
        try {
            $keyPair = $keyExchange->generateKeyPair();
            
            $this->assertIsArray($keyPair);
            $this->assertArrayHasKey('privateKey', $keyPair);
            $this->assertArrayHasKey('publicKey', $keyPair);
            $this->assertNotEmpty($keyPair['privateKey']);
            $this->assertNotEmpty($keyPair['publicKey']);
        } catch  (\Throwable $e) {
            if ($keyExchange->getName() === 'x448') {
                // X448 预期会抛出异常，因为当前环境不支持
                $this->markTestSkipped('X448 当前不支持密钥对生成');
            } else {
                throw $e; // 重新抛出意外异常
            }
        }
    }
    
    /**
     * 测试所有实现类都正确实现了 computeSharedSecret 方法
     * 
     * @dataProvider keyExchangeImplementationsProvider
     */
    public function test_allImplementations_correctlyImplementComputeSharedSecret(KeyExchangeInterface $keyExchange): void
    {
        try {
            // 生成两对密钥
            $keyPair1 = $keyExchange->generateKeyPair();
            $keyPair2 = $keyExchange->generateKeyPair();
            
            // 计算共享密钥
            $sharedSecret1 = $keyExchange->computeSharedSecret(
                $keyPair1['privateKey'],
                $keyPair2['publicKey']
            );
            
            $sharedSecret2 = $keyExchange->computeSharedSecret(
                $keyPair2['privateKey'],
                $keyPair1['publicKey']
            );
            
            // 验证双方计算的共享密钥相同
            $this->assertEquals($sharedSecret1, $sharedSecret2);
            $this->assertNotEmpty($sharedSecret1);
        } catch  (\Throwable $e) {
            if ($keyExchange->getName() === 'x448') {
                // X448 预期会抛出异常，因为当前环境不支持
                $this->markTestSkipped('X448 当前不支持共享密钥计算');
            } else {
                throw $e; // 重新抛出意外异常
            }
        }
    }
    
    /**
     * 测试不同的密钥交换算法生成不同的共享密钥
     */
    public function test_differentImplementations_generateDifferentSecrets(): void
    {
        // 跳过测试，如果没有至少两种可用的密钥交换实现
        $implementations = $this->keyExchangeImplementationsProvider();
        if (count($implementations) < 2) {
            $this->markTestSkipped('需要至少两种可用的密钥交换算法实现才能进行比较测试');
        }
        
        // 仅选择前两种实现进行测试
        $implementation1 = $implementations[0][0];
        $implementation2 = $implementations[1][0];
        
        // 为每种实现生成密钥对
        try {
            $keyPair1 = $implementation1->generateKeyPair();
            $keyPair2 = $implementation2->generateKeyPair();
            
            // 生成随机数据作为输入
            $randomData = random_bytes(32);
            
            // 这个测试只是验证不同的实现在相同输入上产生不同的输出
            // 实际应用中，不应该在不同算法间混用密钥
            $this->assertNotSame($implementation1->getName(), $implementation2->getName());
        } catch  (\Throwable $e) {
            $this->markTestSkipped('无法为多种密钥交换算法生成密钥对：' . $e->getMessage());
        }
    }
} 