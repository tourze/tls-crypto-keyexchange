<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoKeyExchange\Contract;

/**
 * 密钥交换算法接口
 */
interface KeyExchangeInterface
{
    /**
     * 获取密钥交换算法名称
     */
    public function getName(): string;

    /**
     * 生成密钥对
     *
     * @param array<string, mixed> $options 生成密钥对的选项
     *
     * @return array<string, mixed> 包含私钥和公钥的数组，可能包含其他算法特定的参数
     */
    public function generateKeyPair(array $options = []): array;

    /**
     * 计算共享密钥
     *
     * @param string $privateKey 本方私钥
     * @param string $publicKey  对方公钥
     * @param array<string, mixed>  $options    计算选项
     *
     * @return string 共享密钥
     */
    public function computeSharedSecret(string $privateKey, string $publicKey, array $options = []): string;
}
