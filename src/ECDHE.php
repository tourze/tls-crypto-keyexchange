<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange;

use Tourze\TLSCryptoKeyExchange\Contract\KeyExchangeInterface;
use Tourze\TLSCryptoKeyExchange\Exception\GenericKeyExchangeException;

/**
 * ECDHE密钥交换算法实现
 *
 * 椭圆曲线Diffie-Hellman密钥交换（临时版）
 */
class ECDHE implements KeyExchangeInterface
{
    /**
     * 默认使用的曲线
     */
    private const DEFAULT_CURVE = 'prime256v1'; // 即NIST P-256

    /**
     * 默认ECDHE使用的哈希算法
     */
    private const DEFAULT_HASH = 'sha256';

    /**
     * 获取密钥交换算法名称
     */
    public function getName(): string
    {
        return 'ecdhe';
    }

    /**
     * 生成密钥对
     *
     * @param array<string, mixed> $options 生成密钥对的选项
     *
     * @return array<string, mixed> 包含私钥和公钥的数组，可能包含其他算法特定的参数
     *
     * @throws GenericKeyExchangeException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        $curve = $options['curve'] ?? self::DEFAULT_CURVE;

        $this->validateOpenSSLExtension();
        $this->validateCurveSupported($curve);

        return $this->createECKeyPair($curve);
    }

    /**
     * 计算共享密钥
     *
     * @param string $privateKey 本方私钥 (PEM格式)
     * @param string $publicKey  对方公钥 (PEM格式)
     * @param array<string, mixed>  $options    计算选项
     *
     * @return string 共享密钥
     *
     * @throws GenericKeyExchangeException 如果计算共享密钥失败
     */
    public function computeSharedSecret(string $privateKey, string $publicKey, array $options = []): string
    {
        $this->validateOpenSSLExtension();

        try {
            $keyPair = $this->loadAndValidateKeys($privateKey, $publicKey);
            $sharedSecret = $this->performKeyExchange($keyPair['private'], $keyPair['public'], $keyPair['privateDetails']);

            $hashAlgorithm = $options['hash'] ?? self::DEFAULT_HASH;

            return hash($hashAlgorithm, $sharedSecret, true);
        } catch (\Throwable $e) {
            throw new GenericKeyExchangeException('ECDHE共享密钥计算失败: ' . $e->getMessage());
        }
    }

    /**
     * 验证OpenSSL扩展是否可用
     *
     * @throws GenericKeyExchangeException 如果OpenSSL扩展未加载
     */
    private function validateOpenSSLExtension(): void
    {
        if (!extension_loaded('openssl')) {
            throw new GenericKeyExchangeException('OpenSSL扩展未加载，无法使用ECDHE');
        }
    }

    /**
     * 验证椭圆曲线是否受支持
     *
     * @param string $curve 椭圆曲线名称
     *
     * @throws GenericKeyExchangeException 如果曲线不受支持
     */
    private function validateCurveSupported(string $curve): void
    {
        try {
            $supportedCurves = openssl_get_curve_names();
            if (false === $supportedCurves) {
                throw new GenericKeyExchangeException('无法获取支持的椭圆曲线列表');
            }
        } catch (\Throwable $e) {
            throw new GenericKeyExchangeException('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }

        if (!in_array($curve, $supportedCurves, true)) {
            throw new GenericKeyExchangeException('不支持的椭圆曲线: ' . $curve);
        }
    }

    /**
     * 创建EC密钥对
     *
     * @param string $curve 椭圆曲线名称
     *
     * @return array<string, mixed> 包含私钥和公钥的数组，可能包含其他算法特定的参数
     *
     * @throws GenericKeyExchangeException 如果创建密钥对失败
     */
    private function createECKeyPair(string $curve): array
    {
        try {
            $config = [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => $curve,
            ];

            $privateKey = @openssl_pkey_new($config);
            if (false === $privateKey) {
                $error = openssl_error_string();
                throw new GenericKeyExchangeException('ECDHE密钥对生成失败: ' . (false !== $error ? $error : '未知错误'));
            }

            $keyDetails = $this->getKeyDetails($privateKey);
            $privateKeyPem = $this->exportPrivateKey($privateKey);

            return [
                'privateKey' => $privateKeyPem,
                'publicKey' => $keyDetails['key'],
                'curve' => $curve,
            ];
        } catch (GenericKeyExchangeException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new GenericKeyExchangeException('ECDHE密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 获取密钥详情
     *
     * @param \OpenSSLAsymmetricKey $privateKey 私钥资源
     *
     * @return array<string, mixed> 密钥详情
     *
     * @throws GenericKeyExchangeException 如果获取失败
     */
    private function getKeyDetails(\OpenSSLAsymmetricKey $privateKey): array
    {
        $keyDetails = @openssl_pkey_get_details($privateKey);
        if (false === $keyDetails) {
            $error = openssl_error_string();
            throw new GenericKeyExchangeException('无法获取ECDHE密钥细节: ' . (false !== $error ? $error : '未知错误'));
        }

        return $keyDetails;
    }

    /**
     * 导出私钥为PEM格式
     *
     * @param \OpenSSLAsymmetricKey $privateKey 私钥资源
     *
     * @return string PEM格式的私钥
     *
     * @throws GenericKeyExchangeException 如果导出失败
     */
    private function exportPrivateKey(\OpenSSLAsymmetricKey $privateKey): string
    {
        $privateKeyPem = '';
        if (!@openssl_pkey_export($privateKey, $privateKeyPem)) {
            $error = openssl_error_string();
            throw new GenericKeyExchangeException('导出ECDHE私钥失败: ' . (false !== $error ? $error : '未知错误'));
        }

        return $privateKeyPem;
    }

    /**
     * 加载并验证密钥对
     *
     * @param string $privateKey 私钥PEM格式
     * @param string $publicKey  公钥PEM格式
     *
     * @return array<string, mixed> 包含验证后的密钥资源
     *
     * @throws GenericKeyExchangeException 如果密钥无效
     */
    private function loadAndValidateKeys(string $privateKey, string $publicKey): array
    {
        $privKey = openssl_pkey_get_private($privateKey);
        if (false === $privKey) {
            throw new GenericKeyExchangeException('无效的ECDHE私钥: ' . openssl_error_string());
        }

        $pubKey = openssl_pkey_get_public($publicKey);
        if (false === $pubKey) {
            throw new GenericKeyExchangeException('无效的ECDHE公钥: ' . openssl_error_string());
        }

        $privKeyDetails = $this->validateECKey($privKey, '私钥');
        $pubKeyDetails = $this->validateECKey($pubKey, '公钥');

        $this->validateCurveMatch($privKeyDetails, $pubKeyDetails);

        return [
            'private' => $privKey,
            'public' => $pubKey,
            'privateDetails' => $privKeyDetails,
        ];
    }

    /**
     * 验证EC密钥类型
     *
     * @param \OpenSSLAsymmetricKey $key     密钥资源
     * @param string                $keyType 密钥类型描述
     *
     * @return array<string, mixed> 密钥详情
     *
     * @throws GenericKeyExchangeException 如果密钥类型无效
     */
    private function validateECKey(\OpenSSLAsymmetricKey $key, string $keyType): array
    {
        $keyDetails = openssl_pkey_get_details($key);
        if (false === $keyDetails || OPENSSL_KEYTYPE_EC !== $keyDetails['type']) {
            throw new GenericKeyExchangeException($keyType . '不是有效的EC密钥');
        }

        return $keyDetails;
    }

    /**
     * 验证两个密钥使用相同的椭圆曲线
     *
     * @param array<string, mixed> $privKeyDetails 私钥详情
     * @param array<string, mixed> $pubKeyDetails  公钥详情
     *
     * @throws GenericKeyExchangeException 如果曲线不匹配
     */
    private function validateCurveMatch(array $privKeyDetails, array $pubKeyDetails): void
    {
        if ($privKeyDetails['ec']['curve_name'] !== $pubKeyDetails['ec']['curve_name']) {
            throw new GenericKeyExchangeException(sprintf('椭圆曲线不匹配：私钥使用 %s，公钥使用 %s', $privKeyDetails['ec']['curve_name'], $pubKeyDetails['ec']['curve_name']));
        }
    }

    /**
     * 执行密钥交换
     *
     * @param \OpenSSLAsymmetricKey $privKey        私钥资源
     * @param \OpenSSLAsymmetricKey $pubKey         公钥资源
     * @param array<string, mixed>                 $privKeyDetails 私钥详情
     *
     * @return string 共享密钥
     *
     * @throws GenericKeyExchangeException 如果密钥交换失败
     */
    private function performKeyExchange(\OpenSSLAsymmetricKey $privKey, \OpenSSLAsymmetricKey $pubKey, array $privKeyDetails): string
    {
        if (function_exists('openssl_pkey_derive')) {
            return $this->useModernKeyExchange($pubKey, $privKey);
        }

        return $this->useLegacyKeyExchange($privKey, $privKeyDetails);
    }

    /**
     * 使用现代PHP版本的密钥交换方法
     *
     * @param \OpenSSLAsymmetricKey $pubKey  公钥资源
     * @param \OpenSSLAsymmetricKey $privKey 私钥资源
     *
     * @return string 共享密钥
     *
     * @throws GenericKeyExchangeException 如果密钥交换失败
     */
    private function useModernKeyExchange(\OpenSSLAsymmetricKey $pubKey, \OpenSSLAsymmetricKey $privKey): string
    {
        $sharedSecret = openssl_pkey_derive($pubKey, $privKey);
        if (false === $sharedSecret) {
            throw new GenericKeyExchangeException('ECDHE共享密钥导出失败: ' . openssl_error_string());
        }

        return $sharedSecret;
    }

    /**
     * 使用旧版PHP的密钥交换方法
     *
     * @param \OpenSSLAsymmetricKey $privKey        私钥资源
     * @param array<string, mixed>                 $privKeyDetails 私钥详情
     *
     * @return string 共享密钥
     *
     * @throws GenericKeyExchangeException 如果密钥交换失败
     */
    private function useLegacyKeyExchange(\OpenSSLAsymmetricKey $privKey, array $privKeyDetails): string
    {
        throw new GenericKeyExchangeException('当前PHP版本不支持ECDHE点乘法操作。请升级到PHP 8.0或更高版本以使用openssl_pkey_derive函数。');
    }
}
