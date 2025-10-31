<?php

namespace Tourze\TLSCryptoKeyExchange\Tests\KeyExchange;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidParameterException;
use Tourze\TLSCryptoKeyExchange\KeyExchange\RSAKeyExchange;

/**
 * RSA密钥交换测试
 *
 * @internal
 */
#[CoversClass(RSAKeyExchange::class)]
final class RSAKeyExchangeTest extends TestCase
{
    /**
     * 测试公钥设置和获取
     */
    public function testSetAndGetServerPublicKey(): void
    {
        $exchange = new RSAKeyExchange();
        $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqUm\ntYTNPYQGQykP0GCc\n1SecN4PXgbgokH+NE5oK3M/hCYV2FfvtgcuaKrWrLzN3IFS\nFKWXm6UZ5AhvBnQQP\nxLKHx3Pu4Q==\n-----END PUBLIC KEY-----";

        $exchange->setServerPublicKey($publicKey);
        $this->assertEquals($publicKey, $exchange->getServerPublicKey());
    }

    /**
     * 测试生成预主密钥
     */
    public function testGeneratePreMasterSecret(): void
    {
        $exchange = new RSAKeyExchange();
        $version = 0x0303; // TLS 1.2

        $preMasterSecret = $exchange->generatePreMasterSecret($version);

        // 验证长度为48字节（2字节版本号 + 46字节随机数据）
        $this->assertEquals(48, strlen($preMasterSecret));

        // 验证前两个字节是版本号
        $unpacked = unpack('n', substr($preMasterSecret, 0, 2));
        $this->assertIsArray($unpacked);
        $this->assertEquals($version, $unpacked[1]);
    }

    /**
     * 测试加密预主密钥
     */
    public function testEncryptPreMasterSecret(): void
    {
        // 生成一个测试用的RSA密钥对
        $keyPair = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $this->assertNotFalse($keyPair, 'Failed to generate RSA key pair');

        // 获取公钥
        $publicKeyDetails = openssl_pkey_get_details($keyPair);
        $this->assertIsArray($publicKeyDetails);
        $publicKey = $publicKeyDetails['key'];

        $exchange = new RSAKeyExchange();
        $exchange->setServerPublicKey($publicKey);
        $exchange->generatePreMasterSecret(0x0303);

        $encryptedData = $exchange->encryptPreMasterSecret();

        // 验证加密数据不为空且长度合理
        $this->assertNotEmpty($encryptedData);
        $this->assertGreaterThan(100, strlen($encryptedData)); // RSA 2048位加密后应该有256字节
    }

    /**
     * 测试解密预主密钥
     */
    public function testDecryptPreMasterSecret(): void
    {
        // 生成一个测试用的RSA密钥对
        $keyPair = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $this->assertNotFalse($keyPair, 'Failed to generate RSA key pair');

        // 获取公钥和私钥
        $publicKeyDetails = openssl_pkey_get_details($keyPair);
        $this->assertIsArray($publicKeyDetails);
        $publicKey = $publicKeyDetails['key'];

        $privateKey = '';
        $result = openssl_pkey_export($keyPair, $privateKey);
        $this->assertTrue($result);

        $exchange = new RSAKeyExchange();
        $exchange->setServerPublicKey($publicKey);
        $originalPreMasterSecret = $exchange->generatePreMasterSecret(0x0303);

        // 加密预主密钥
        $encryptedData = $exchange->encryptPreMasterSecret();

        // 解密预主密钥
        $decryptedSecret = $exchange->decryptPreMasterSecret($encryptedData, $privateKey);

        // 验证解密后的预主密钥与原始的相同
        $this->assertEquals($originalPreMasterSecret, $decryptedSecret);
        $this->assertEquals(48, strlen($decryptedSecret)); // 预主密钥应该是48字节
    }

    /**
     * 测试没有生成预主密钥时加密抛出异常
     */
    public function testEncryptWithoutPreMasterSecretThrowsException(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('Pre-master secret not generated');

        $exchange = new RSAKeyExchange();
        $exchange->setServerPublicKey("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqUm\ntYTNPYQGQykP0GCc\n1SecN4PXgbgokH+NE5oK3M/hCYV2FfvtgcuaKrWrLzN3IFS\nFKWXm6UZ5AhvBnQQP\nxLKHx3Pu4Q==\n-----END PUBLIC KEY-----");
        $exchange->encryptPreMasterSecret();
    }

    /**
     * 测试没有设置服务器公钥时加密抛出异常
     */
    public function testEncryptWithoutServerPublicKeyThrowsException(): void
    {
        $this->expectException(InvalidParameterException::class);
        $this->expectExceptionMessage('Server public key not set');

        $exchange = new RSAKeyExchange();
        $exchange->generatePreMasterSecret(0x0303);
        $exchange->encryptPreMasterSecret();
    }
}
