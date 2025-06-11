<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange;

use Tourze\TLSCryptoKeyExchange\Contract\KeyExchangeInterface;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

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
     *
     * @return string
     */
    public function getName(): string
    {
        return 'ecdhe';
    }

    /**
     * 生成密钥对
     *
     * @param array $options 生成密钥对的选项
     * @return array 包含私钥和公钥的数组
     * @throws KeyExchangeException 如果生成密钥对失败
     */
    public function generateKeyPair(array $options = []): array
    {
        $curve = $options['curve'] ?? self::DEFAULT_CURVE;

        // 检查OpenSSL是否支持ECDHE
        if (!extension_loaded('openssl')) {
            throw new KeyExchangeException('OpenSSL扩展未加载，无法使用ECDHE');
        }

        // 获取支持的曲线列表
        $supportedCurves = [];
        try {
            $supportedCurves = openssl_get_curve_names();
            if ($supportedCurves === false) {
                throw new KeyExchangeException('无法获取支持的椭圆曲线列表');
            }
        } catch  (\Throwable $e) {
            throw new KeyExchangeException('获取支持的椭圆曲线失败: ' . $e->getMessage());
        }

        if (!in_array($curve, $supportedCurves)) {
            throw new KeyExchangeException('不支持的椭圆曲线: ' . $curve);
        }

        try {
            // 创建ECDSA私钥（ECDHE使用相同的密钥生成机制）
            $config = [
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'curve_name' => $curve,
            ];

            $privateKey = @openssl_pkey_new($config);

            if ($privateKey === false) {
                $error = openssl_error_string();
                throw new KeyExchangeException('ECDHE密钥对生成失败: ' . ($error ?: '未知错误'));
            }

            // 导出私钥细节
            $keyDetails = @openssl_pkey_get_details($privateKey);
            if ($keyDetails === false) {
                $error = openssl_error_string();
                throw new KeyExchangeException('无法获取ECDHE密钥细节: ' . ($error ?: '未知错误'));
            }

            // 导出 PEM 格式的私钥和公钥
            $privateKeyPem = '';
            if (!@openssl_pkey_export($privateKey, $privateKeyPem)) {
                $error = openssl_error_string();
                throw new KeyExchangeException('导出ECDHE私钥失败: ' . ($error ?: '未知错误'));
            }

            $publicKeyPem = $keyDetails['key'];

            return [
                'privateKey' => $privateKeyPem,
                'publicKey' => $publicKeyPem,
                'curve' => $curve,
            ];
        } catch (KeyExchangeException $e) {
            throw $e;
        } catch  (\Throwable $e) {
            throw new KeyExchangeException('ECDHE密钥对生成失败: ' . $e->getMessage());
        }
    }

    /**
     * 计算共享密钥
     *
     * @param string $privateKey 本方私钥 (PEM格式)
     * @param string $publicKey 对方公钥 (PEM格式)
     * @param array $options 计算选项
     * @return string 共享密钥
     * @throws KeyExchangeException 如果计算共享密钥失败
     */
    public function computeSharedSecret(string $privateKey, string $publicKey, array $options = []): string
    {
        // 检查OpenSSL是否可用
        if (!extension_loaded('openssl')) {
            throw new KeyExchangeException('OpenSSL扩展未加载，无法使用ECDHE');
        }

        try {
            // 加载私钥
            $privKey = openssl_pkey_get_private($privateKey);
            if ($privKey === false) {
                throw new KeyExchangeException('无效的ECDHE私钥: ' . openssl_error_string());
            }

            // 加载公钥
            $pubKey = openssl_pkey_get_public($publicKey);
            if ($pubKey === false) {
                throw new KeyExchangeException('无效的ECDHE公钥: ' . openssl_error_string());
            }

            // 检查私钥类型
            $privKeyDetails = openssl_pkey_get_details($privKey);
            if ($privKeyDetails === false || $privKeyDetails['type'] !== OPENSSL_KEYTYPE_EC) {
                throw new KeyExchangeException('私钥不是有效的EC密钥');
            }

            // 检查公钥类型
            $pubKeyDetails = openssl_pkey_get_details($pubKey);
            if ($pubKeyDetails === false || $pubKeyDetails['type'] !== OPENSSL_KEYTYPE_EC) {
                throw new KeyExchangeException('公钥不是有效的EC密钥');
            }

            // 确保两个密钥使用相同的曲线
            if ($privKeyDetails['ec']['curve_name'] !== $pubKeyDetails['ec']['curve_name']) {
                throw new KeyExchangeException(
                    sprintf(
                        '椭圆曲线不匹配：私钥使用 %s，公钥使用 %s',
                        $privKeyDetails['ec']['curve_name'],
                        $pubKeyDetails['ec']['curve_name']
                    )
                );
            }

            // 使用OpenSSL进行椭圆曲线点乘法
            // PHP 8以上支持openssl_pkey_derive函数
            if (function_exists('openssl_pkey_derive')) {
                $sharedSecret = openssl_pkey_derive($pubKey, $privKey);
                if ($sharedSecret === false) {
                    throw new KeyExchangeException('ECDHE共享密钥导出失败: ' . openssl_error_string());
                }
            } else {
                // 对于低版本PHP，我们需要使用替代方法
                // 获取公钥中的椭圆曲线点坐标
                $ecPoint = $this->extractECPoint($publicKey);

                // 使用私钥对点进行运算
                // 注意：这是一个回退实现，应尽可能使用openssl_pkey_derive
                $tmpKeyResource = openssl_pkey_new([
                    'private_key_type' => OPENSSL_KEYTYPE_EC,
                    'curve_name' => $privKeyDetails['ec']['curve_name'],
                ]);

                if ($tmpKeyResource === false) {
                    throw new KeyExchangeException('临时EC密钥创建失败: ' . openssl_error_string());
                }

                $result = '';
                // 尝试通过私钥解密操作来模拟ECDH点乘法
                // 这不是标准操作，但在某些版本的OpenSSL中可能有效
                $success = openssl_private_decrypt($ecPoint, $result, $privKey, OPENSSL_NO_PADDING);

                if (!$success || empty($result)) {
                    throw new KeyExchangeException(
                        '当前PHP版本不支持ECDHE点乘法操作。请升级到PHP 8.0或更高版本以使用openssl_pkey_derive函数。'
                    );
                }

                $sharedSecret = $result;
            }

            // 对共享密钥进行哈希处理
            $hashAlgorithm = $options['hash'] ?? self::DEFAULT_HASH;
            return hash($hashAlgorithm, $sharedSecret, true);
        } catch  (\Throwable $e) {
            throw new KeyExchangeException('ECDHE共享密钥计算失败: ' . $e->getMessage());
        }
    }

    /**
     * 从公钥中提取EC点数据
     *
     * @param string $publicKey PEM格式的公钥
     * @return string 提取出的EC点数据（二进制格式）
     * @throws KeyExchangeException 如果提取失败
     */
    private function extractECPoint(string $publicKey): string
    {
        try {
            $pubKey = openssl_pkey_get_public($publicKey);
            if ($pubKey === false) {
                throw new KeyExchangeException('加载EC公钥失败: ' . openssl_error_string());
            }

            $details = openssl_pkey_get_details($pubKey);
            if ($details === false || !isset($details['ec']['x']) || !isset($details['ec']['y'])) {
                throw new KeyExchangeException('无法从公钥中提取EC点数据');
            }

            // EC点数据格式: 0x04 + x坐标 + y坐标
            $ecPoint = "\x04" . $details['ec']['x'] . $details['ec']['y'];

            return $ecPoint;
        } catch  (\Throwable $e) {
            throw new KeyExchangeException('提取EC点数据失败: ' . $e->getMessage());
        }
    }
}
