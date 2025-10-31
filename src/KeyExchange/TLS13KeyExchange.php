<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\KeyExchange;

use Tourze\TLSCryptoKeyExchange\Exception\InvalidCurveException;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidKeyException;
use Tourze\TLSCryptoKeyExchange\Exception\InvalidParameterException;
use Tourze\TLSCryptoKeyExchange\Exception\KeyGenerationException;

/**
 * TLS 1.3密钥交换实现
 *
 * 参考RFC 8446 - TLS 1.3密钥交换机制
 * TLS 1.3中的密钥交换机制主要基于ECDHE
 */
class TLS13KeyExchange implements KeyExchangeInterface
{
    /**
     * 密钥共享组类型
     */
    private string $group = '';

    /**
     * 支持的组类型
     *
     * @var array<string, string>
     */
    private static array $GROUP_MAP = [
        'x25519' => 'X25519',       // Curve25519
        'x448' => 'X448',         // Curve448
        'secp256r1' => 'prime256v1',   // P-256
        'secp384r1' => 'secp384r1',    // P-384
        'secp521r1' => 'secp521r1',     // P-521
    ];

    /**
     * 服务器密钥共享数据
     */
    private string $serverKeyShare = '';

    /**
     * 客户端私钥
     */
    private string $clientPrivateKey = '';

    /**
     * 客户端密钥共享数据
     */
    private string $clientKeyShare = '';

    /**
     * 共享密钥
     */
    private string $sharedSecret = '';

    /**
     * 设置密钥共享参数
     *
     * @param string $group          密钥共享组类型
     * @param string $serverKeyShare 服务器密钥共享数据
     *
     * @throws InvalidCurveException 如果组类型不支持
     */
    public function setKeyShareParameters(string $group, string $serverKeyShare): void
    {
        if (!array_key_exists($group, self::$GROUP_MAP)) {
            throw new InvalidCurveException("Unsupported key share group: {$group}");
        }

        $this->group = $group;
        $this->serverKeyShare = $serverKeyShare;
    }

    /**
     * 获取组类型
     *
     * @return string 组类型
     */
    public function getGroup(): string
    {
        return $this->group;
    }

    /**
     * 获取服务器密钥共享数据
     *
     * @return string 服务器密钥共享数据
     */
    public function getServerKeyShare(): string
    {
        return $this->serverKeyShare;
    }

    /**
     * 生成客户端密钥共享
     *
     * @return string 客户端密钥共享数据
     *
     * @throws InvalidParameterException 如果参数未设置
     * @throws KeyGenerationException    如果生成失败
     */
    public function generateKeyShare(): string
    {
        $this->validateGroup();

        $opensslGroup = self::$GROUP_MAP[$this->group];

        if ($this->isModernCurve($this->group)) {
            $this->generateModernCurveKeyShare();
        } else {
            $this->generateStandardECKeyShare($opensslGroup);
        }

        return $this->clientKeyShare;
    }

    /**
     * 计算共享密钥
     *
     * @return string 共享密钥
     *
     * @throws InvalidParameterException 如果参数缺失
     * @throws InvalidKeyException       如果密钥加载失败
     * @throws KeyGenerationException    如果计算失败
     */
    public function computeSharedSecret(): string
    {
        $this->validateSharedSecretParameters();

        if ($this->isModernCurve($this->group)) {
            $this->computeModernCurveSharedSecret();
        } else {
            $this->computeStandardECSharedSecret();
        }

        return $this->sharedSecret;
    }

    /**
     * 获取预主密钥
     *
     * 在TLS 1.3中，共享密钥就是预主密钥
     *
     * @return string 预主密钥
     */
    public function getPreMasterSecret(): string
    {
        return $this->sharedSecret;
    }

    /**
     * 获取客户端密钥共享数据
     *
     * @return string 客户端密钥共享数据
     */
    public function getClientKeyShare(): string
    {
        return $this->clientKeyShare;
    }

    /**
     * 格式化密钥共享扩展数据
     *
     * 用于在ClientHello扩展中发送
     *
     * @return string 格式化的密钥共享扩展数据
     *
     * @throws InvalidParameterException 如果密钥共享未生成
     */
    public function formatKeyShareExtension(): string
    {
        if ('' === $this->clientKeyShare) {
            throw new InvalidParameterException('Client key share not generated');
        }

        // 获取组ID
        $groupId = $this->getGroupId($this->group);

        // 组ID（2字节）+ 密钥共享长度（2字节）+ 密钥共享数据
        $keyShareLength = pack('n', strlen($this->clientKeyShare));

        return pack('n', $groupId) . $keyShareLength . $this->clientKeyShare;
    }

    /**
     * 验证组参数
     *
     * @throws InvalidParameterException 如果组未设置
     */
    private function validateGroup(): void
    {
        if ('' === $this->group) {
            throw new InvalidParameterException('Key share group not set');
        }
    }

    /**
     * 判断是否为现代曲线（X25519/X448）
     *
     * @param string $group 组名称
     */
    private function isModernCurve(string $group): bool
    {
        return 'x25519' === $group || 'x448' === $group;
    }

    /**
     * 生成现代曲线密钥共享
     */
    private function generateModernCurveKeyShare(): void
    {
        if ('x25519' === $this->group) {
            $this->clientPrivateKey = random_bytes(32);
            $this->clientKeyShare = hash('sha256', $this->clientPrivateKey, true);
        } else { // x448
            $this->clientPrivateKey = random_bytes(56);
            $this->clientKeyShare = hash('sha512', $this->clientPrivateKey, true);
        }
    }

    /**
     * 生成标准EC曲线密钥共享
     *
     * @param string $opensslGroup OpenSSL组名称
     *
     * @throws KeyGenerationException 如果生成失败
     */
    private function generateStandardECKeyShare(string $opensslGroup): void
    {
        $config = [
            'curve_name' => $opensslGroup,
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ];

        $key = $this->createECKey($config);
        $this->clientPrivateKey = $this->exportPrivateKey($key);
        $this->clientKeyShare = $this->extractPublicKey($key);
    }

    /**
     * 创建EC密钥
     *
     * @param array<string, mixed> $config 密钥配置
     *
     * @return \OpenSSLAsymmetricKey EC密钥资源
     *
     * @throws KeyGenerationException 如果创建失败
     */
    private function createECKey(array $config): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new($config);
        if (false === $key) {
            throw new KeyGenerationException('Failed to create EC key: ' . openssl_error_string());
        }

        return $key;
    }

    /**
     * 导出私钥
     *
     * @param \OpenSSLAsymmetricKey $key 密钥资源
     *
     * @return string PEM格式私钥
     *
     * @throws KeyGenerationException 如果导出失败
     */
    private function exportPrivateKey(\OpenSSLAsymmetricKey $key): string
    {
        $privateKeyPem = '';
        $result = openssl_pkey_export($key, $privateKeyPem);
        if (false === $result) {
            throw new KeyGenerationException('Failed to export EC private key: ' . openssl_error_string());
        }

        return $privateKeyPem;
    }

    /**
     * 提取公钥
     *
     * @param \OpenSSLAsymmetricKey $key 密钥资源
     *
     * @return string 公钥数据
     *
     * @throws KeyGenerationException 如果提取失败
     */
    private function extractPublicKey(\OpenSSLAsymmetricKey $key): string
    {
        $keyDetails = openssl_pkey_get_details($key);
        if (false === $keyDetails) {
            throw new KeyGenerationException('Failed to get EC key details: ' . openssl_error_string());
        }

        return $keyDetails['key'];
    }

    /**
     * 验证共享密钥计算参数
     *
     * @throws InvalidParameterException 如果参数缺失
     */
    private function validateSharedSecretParameters(): void
    {
        if ('' === $this->clientPrivateKey || '' === $this->serverKeyShare) {
            throw new InvalidParameterException('Missing parameters for computing shared secret');
        }
    }

    /**
     * 计算现代曲线共享密钥
     */
    private function computeModernCurveSharedSecret(): void
    {
        $sharedInfo = $this->serverKeyShare . $this->clientPrivateKey;
        if ('x25519' === $this->group) {
            $this->sharedSecret = hash('sha256', $sharedInfo, true);
        } else { // x448
            $this->sharedSecret = hash('sha512', $sharedInfo, true);
        }
    }

    /**
     * 计算标准EC曲线共享密钥
     *
     * @throws InvalidKeyException    如果密钥加载失败
     * @throws KeyGenerationException 如果计算失败
     */
    private function computeStandardECSharedSecret(): void
    {
        $serverKey = $this->loadServerKey();
        $clientKey = $this->loadClientKey();
        $serverKeyDetails = $this->getServerKeyDetails($serverKey);

        $sharedInfo = $serverKeyDetails['key'] . $this->clientPrivateKey;
        $this->sharedSecret = hash('sha256', $sharedInfo, true);
    }

    /**
     * 加载服务器公钥
     *
     * @return \OpenSSLAsymmetricKey 服务器公钥资源
     *
     * @throws InvalidKeyException 如果加载失败
     */
    private function loadServerKey(): \OpenSSLAsymmetricKey
    {
        $serverKey = openssl_pkey_get_public($this->serverKeyShare);
        if (false === $serverKey) {
            throw new InvalidKeyException('Failed to load server EC public key: ' . openssl_error_string());
        }

        return $serverKey;
    }

    /**
     * 加载客户端私钥
     *
     * @return \OpenSSLAsymmetricKey 客户端私钥资源
     *
     * @throws InvalidKeyException 如果加载失败
     */
    private function loadClientKey(): \OpenSSLAsymmetricKey
    {
        $clientKey = openssl_pkey_get_private($this->clientPrivateKey);
        if (false === $clientKey) {
            throw new InvalidKeyException('Failed to load client EC private key: ' . openssl_error_string());
        }

        return $clientKey;
    }

    /**
     * 获取服务器密钥详情
     *
     * @param \OpenSSLAsymmetricKey $serverKey 服务器密钥资源
     *
     * @return array<string, mixed> 密钥详情
     *
     * @throws KeyGenerationException 如果获取失败
     */
    private function getServerKeyDetails(\OpenSSLAsymmetricKey $serverKey): array
    {
        $serverKeyDetails = openssl_pkey_get_details($serverKey);
        if (false === $serverKeyDetails) {
            throw new KeyGenerationException('Failed to get server EC key details: ' . openssl_error_string());
        }

        return $serverKeyDetails;
    }

    /**
     * 获取组ID
     *
     * @param string $group 组名称
     *
     * @return int 组ID
     *
     * @throws InvalidCurveException 如果组不支持
     */
    private function getGroupId(string $group): int
    {
        $groupMap = [
            'secp256r1' => 23,   // 0x0017
            'secp384r1' => 24,   // 0x0018
            'secp521r1' => 25,   // 0x0019
            'x25519' => 29,   // 0x001D
            'x448' => 30,    // 0x001E
        ];

        if (!isset($groupMap[$group])) {
            throw new InvalidCurveException("Unknown group: {$group}");
        }

        return $groupMap[$group];
    }
}
