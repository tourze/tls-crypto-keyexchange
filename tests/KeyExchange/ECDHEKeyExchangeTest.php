<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Tests\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\KeyExchange\ECDHEKeyExchange;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidCurveException;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidParameterException;

/**
 * ECDHE密钥交换测试
 */
class ECDHEKeyExchangeTest extends TestCase
{
    private ECDHEKeyExchange $keyExchange;
    
    protected function setUp(): void
    {
        $this->keyExchange = new ECDHEKeyExchange();
    }
    
    public function testSetECParametersWithValidCurve(): void
    {
        $curve = 'secp256r1';
        $serverPublicKey = '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5xFojouibV6qLNy4vA+EZJMPaWNy
mf8pBhJpu7T2S5JH1CB2qFjd8JYx/Y0rV/3riKFg/xrXGSVPAd3bULNrXg==
-----END PUBLIC KEY-----';
        
        $result = $this->keyExchange->setECParameters($curve, $serverPublicKey);
        
        $this->assertSame($this->keyExchange, $result);
        $this->assertEquals($curve, $this->keyExchange->getCurve());
        $this->assertEquals($serverPublicKey, $this->keyExchange->getServerPublicKey());
    }
    
    public function testSetECParametersWithInvalidCurve(): void
    {
        $this->expectException(InvalidCurveException::class);
        $this->expectExceptionMessage('Unsupported elliptic curve: invalid_curve');
        
        $this->keyExchange->setECParameters('invalid_curve', 'dummy_key');
    }
    
    public function testGenerateClientKeyPairWithoutParameters(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('EC parameters not set');
        
        $this->keyExchange->generateClientKeyPair();
    }
    
    public function testComputePreMasterSecretWithoutParameters(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('Missing parameters for computing pre-master secret');
        
        $this->keyExchange->computePreMasterSecret();
    }
    
    public function testSupportedCurves(): void
    {
        $supportedCurves = ['secp256r1', 'secp384r1', 'secp521r1', 'x25519'];
        
        foreach ($supportedCurves as $curve) {
            $keyExchange = new ECDHEKeyExchange();
            $keyExchange->setECParameters($curve, 'dummy_key');
            $this->assertEquals($curve, $keyExchange->getCurve());
        }
    }
}