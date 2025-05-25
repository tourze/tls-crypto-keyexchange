<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange;

use Tourze\TLSCryptoKeyExchange\Contract\KeyExchangeInterface;
use Tourze\TLSCryptoKeyExchange\Exception\KeyExchangeException;

/**
 * DHE密钥交换算法实现
 *
 * Diffie-Hellman密钥交换（临时版）
 */
class DHE implements KeyExchangeInterface
{
    /**
     * DHE标准参数组名称到十六进制素数和生成器g的映射。
     * 素数来自 RFC 3526 (MODP Groups for IKE)
     */
    private const DH_STANDARD_GROUPS = [
        'ffdhe2048' => [
            'p_hex' => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
            'g' => 2,
            'bits' => 2048,
        ],
        'ffdhe3072' => [
            // 为奇数长度的十六进制字符串添加前导0，修复hex2bin转换问题
            'p_hex' => '0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8887464EDA5FBD55381EF92F820D085785A38A071FD3A96237BD642348B04DE4F787C025769532707863364415069474CF72934E047C04D94288021E78692A55053420853D518491E14A33F3E50D78F303A3F346EFD6AD24644688226516731A416964657A79AF4AE5B193B8839069DE183B0DA23FF9B03B49A5F2278A82F1E974E0F9BF908E6F9D840A9A4E40A5F285D4001FFFFFFFFFFFFFFFF',
            'g' => 2,
            'bits' => 3072,
        ],
        'ffdhe4096' => [
            'p_hex' => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8887464EDA5FBD55381EF92F820D085785A38A071FD3A96237BD642348B04DE4F787C025769532707863364415069474CF72934E047C04D94288021E78692A55053420853D518491E14A33F3E50D78F303A3F346EFD6AD24644688226516731A416964657A79AF4AE5B193B8839069DE183B0DA23FF9B03B49A5F2278A82F1E974E0F9BF908E6F9D840A9A4E40A5F285D400105EF233937303B4E924B826D8428542D1B9055E5020176D4421B44D24044400824589A4A074A5304222A730691D167A647635BE9976092543529E87A88EB0F33A30E0321780E1052A788E46123BEF181BF95A691418A84E47B2C917498D67084444D41566B2550312093678B78879249869A1BB1804F27383A1158968D070BB88240734E144515454D858FDA99333A9D3F4AE6A403746E31FFDF429A51482F98E3BCB655BF50944988767C9D478D070E0BBD3026029477F7D73622F9AB073EFF001FFFFFFFFFFFFFFFF',
            'g' => 2,
            'bits' => 4096,
        ],
    ];

    private const DEFAULT_GROUP_NAME = 'ffdhe2048';

    /**
     * 默认DHE使用的哈希算法
     */
    private const DEFAULT_HASH = 'sha256';

    /**
     * 缓存的二进制素数，避免重复转换
     */
    private static $binary_primes = [];

    /**
     * 将十六进制字符串素数转换为二进制
     */
    private function hexToBinary(string $hex): string
    {
        $bin = @hex2bin($hex);
        if ($bin === false) {
            throw new KeyExchangeException('无法将十六进制字符串转换为二进制，可能包含无效的字符或长度为奇数');
        }
        return $bin;
    }

    /**
     * 获取密钥交换算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'dhe';
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
        $groupName = $options['group'] ?? self::DEFAULT_GROUP_NAME;
        $actualGroupName = $groupName; // Store the initially requested or default group name

        if (!extension_loaded('openssl')) {
            throw new KeyExchangeException('OpenSSL扩展未加载，无法使用DHE');
        }

        if (!isset(self::DH_STANDARD_GROUPS[$groupName])) {
            $actualGroupName = self::DEFAULT_GROUP_NAME; // Fallback to default
        }
        $groupParams = self::DH_STANDARD_GROUPS[$actualGroupName];
        $bits = $groupParams['bits'];

        try {
            // 从缓存中获取二进制素数，或者进行转换并缓存结果
            if (!isset(self::$binary_primes[$actualGroupName])) {
                self::$binary_primes[$actualGroupName] = $this->hexToBinary($groupParams['p_hex']);
            }
            $p_bin = self::$binary_primes[$actualGroupName];

            $dhPKeyResource = openssl_pkey_new([
                'private_key_type' => OPENSSL_KEYTYPE_DH,
                'dh' => [
                    'p' => $p_bin,
                    'g' => pack('C', $groupParams['g']), // pack 'g' as an unsigned char (binary)
                ],
            ]);

            if ($dhPKeyResource === false) {
                throw new KeyExchangeException('DHE密钥对生成失败 (pkey_new): ' . openssl_error_string());
            }

            $keyDetails = openssl_pkey_get_details($dhPKeyResource);
            if ($keyDetails === false || !isset($keyDetails['dh'])) {
                throw new KeyExchangeException('无法获取DHE密钥细节: ' . openssl_error_string());
            }

            $privateKeyPem = '';
            if (!openssl_pkey_export($dhPKeyResource, $privateKeyPem)) {
                throw new KeyExchangeException('导出DHE私钥失败: ' . openssl_error_string());
            }

            $publicKeyPem = $keyDetails['key']; // This is the public key in PEM format

            return [
                'privateKey' => $privateKeyPem,
                'publicKey' => $publicKeyPem,
                'params' => $keyDetails['dh'], // Contains p, g, pub_key, priv_key if available
                'group' => $actualGroupName, // Return the actual group name used
                'bits' => $bits,
            ];
        } catch (KeyExchangeException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new KeyExchangeException('DHE密钥对生成一般性失败: ' . $e->getMessage(), 0, $e);
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
    public function computeSharedSecret(string $privateKeyPem, string $publicKeyPem, array $options = []): string
    {
        if (!extension_loaded('openssl')) {
            throw new KeyExchangeException('OpenSSL扩展未加载，无法使用DHE');
        }

        try {
            $localPrivKey = openssl_pkey_get_private($privateKeyPem);
            if ($localPrivKey === false) {
                throw new KeyExchangeException('加载DHE私钥失败: ' . openssl_error_string());
            }

            $peerPubKeyResource = openssl_pkey_get_public($publicKeyPem);
            if ($peerPubKeyResource === false) {
                throw new KeyExchangeException('加载DHE公钥失败: ' . openssl_error_string());
            }

            $peerPubKeyDetails = openssl_pkey_get_details($peerPubKeyResource);
            if ($peerPubKeyDetails === false || !isset($peerPubKeyDetails['dh']['pub_key'])) {
                 throw new KeyExchangeException('无法获取对端DHE公钥详情: ' . openssl_error_string());
            }
            $peerPublicValue = $peerPubKeyDetails['dh']['pub_key']; // This is the actual Y_peer as binary

            // openssl_dh_compute_key expects the peer's public key value (not PEM)
            $sharedSecretRaw = openssl_dh_compute_key($peerPublicValue, $localPrivKey);

            if ($sharedSecretRaw === false) {
                throw new KeyExchangeException('DHE共享密钥计算失败 (dh_compute_key): ' . openssl_error_string());
            }

            $hashAlgorithm = $options['hash'] ?? self::DEFAULT_HASH;
            return hash($hashAlgorithm, $sharedSecretRaw, true);
        } catch (KeyExchangeException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new KeyExchangeException('DHE共享密钥计算一般性失败: ' . $e->getMessage(), 0, $e);
        }
    }
}
