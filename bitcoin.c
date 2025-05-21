#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h> // 比特币使用 secp256k1 曲线
#include <openssl/bn.h>

/**
 * @brief 从 ECC 私钥生成公钥，并计算其 SHA256 + RIPEMD160 哈希（公钥哈希）
 * @param priv_key_bytes 输入的私钥（32字节）
 * @param pubkey_hash_out 输出的公钥哈希（20字节）
 * @return 成功返回 1，失败返回 0
 */
int generate_pubkey_hash_from_privkey(const unsigned char *priv_key_bytes, unsigned char *pubkey_hash_out) {
    EC_KEY *key = NULL;
    const EC_GROUP *group = NULL;
    EC_POINT *pub_key = NULL;
    unsigned char *pub_key_bytes = NULL;
    size_t pub_key_len;
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];

    // 创建新的 EC_KEY（使用比特币的 secp256k1 曲线）
    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        fprintf(stderr, "Error: Failed to create EC_KEY\n");
        return 0;
    }

    // 设置私钥
    if (!EC_KEY_oct2priv(key, priv_key_bytes, 32)) {
        fprintf(stderr, "Error: Failed to set private key\n");
        EC_KEY_free(key);
        return 0;
    }

    // 生成公钥
    group = EC_KEY_get0_group(key);
    pub_key = EC_POINT_new(group);
    if (!pub_key) {
        fprintf(stderr, "Error: Failed to create EC_POINT\n");
        EC_KEY_free(key);
        return 0;
    }

    if (!EC_POINT_mul(group, pub_key, EC_KEY_get0_private_key(key), NULL, NULL, NULL)) {
        fprintf(stderr, "Error: Failed to compute public key\n");
        EC_POINT_free(pub_key);
        EC_KEY_free(key);
        return 0;
    }

    // 将公钥转换为压缩格式（33字节，0x02/0x03 + X）
    pub_key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    pub_key_bytes = (unsigned char *)malloc(pub_key_len);
    if (!pub_key_bytes) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        EC_POINT_free(pub_key);
        EC_KEY_free(key);
        return 0;
    }

    EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_COMPRESSED, pub_key_bytes, pub_key_len, NULL);

    // 计算 SHA256(公钥)
    SHA256(pub_key_bytes, pub_key_len, sha256_hash);

    // 计算 RIPEMD160(SHA256(公钥)) → 20 字节公钥哈希
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);

    // 复制到输出
    memcpy(pubkey_hash_out, ripemd160_hash, RIPEMD160_DIGEST_LENGTH);

    // 清理资源
    free(pub_key_bytes);
    EC_POINT_free(pub_key);
    EC_KEY_free(key);

    return 1;
}


/**
 * @brief Base58 解码比特币地址，得到公钥哈希（20字节）
 * @param base58_addr 输入的比特币地址（Base58编码）
 * @param pubkey_hash_out 输出的公钥哈希（20字节）
 * @return 成功返回 1，失败返回 0
 */
int base58_decode_bitcoin_address(const char *base58_addr, unsigned char *pubkey_hash_out) {
    const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    BIGNUM *bn = BN_new();
    BIGNUM *div = BN_new();
    BIGNUM *rem = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *decoded_bytes = NULL;
    int i, j, leading_zeros = 0;
    size_t decoded_len;

    if (!bn || !div || !rem || !ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // 初始化 BN
    BN_zero(bn);

    // Base58 解码
    for (i = 0; base58_addr[i]; i++) {
        const char *p = strchr(base58_chars, base58_addr[i]);
        if (!p) {
            fprintf(stderr, "Error: Invalid Base58 character\n");
            goto cleanup;
        }

        BN_mul_word(bn, 58);
        BN_add_word(bn, p - base58_chars);
    }

    // 计算前导零（比特币地址可能以 '1' 开头）
    for (i = 0; base58_addr[i] == '1'; i++) {
        leading_zeros++;
    }

    // 转换为字节数组
    decoded_len = BN_num_bytes(bn) + leading_zeros;
    decoded_bytes = (unsigned char *)malloc(decoded_len);
    if (!decoded_bytes) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // 填充前导零
    memset(decoded_bytes, 0, leading_zeros);
    BN_bn2bin(bn, decoded_bytes + leading_zeros);

    // 比特币地址结构：1字节版本 + 20字节公钥哈希 + 4字节校验码
    if (decoded_len != 25) {
        fprintf(stderr, "Error: Invalid Bitcoin address length after decoding\n");
        goto cleanup;
    }

    // 校验 checksum (最后4字节是前21字节的双SHA256哈希的前4字节)
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256(decoded_bytes, 21, checksum);
    SHA256(checksum, SHA256_DIGEST_LENGTH, checksum);

    if (memcmp(checksum, decoded_bytes + 21, 4) != 0) {
        fprintf(stderr, "Error: Invalid Bitcoin address checksum\n");
        goto cleanup;
    }

    // 提取公钥哈希（20字节）
    memcpy(pubkey_hash_out, decoded_bytes + 1, 20);

    free(decoded_bytes);
    BN_free(bn);
    BN_free(div);
    BN_free(rem);
    BN_CTX_free(ctx);
    return 1;

cleanup:
    if (decoded_bytes) free(decoded_bytes);
    if (bn) BN_free(bn);
    if (div) BN_free(div);
    if (rem) BN_free(rem);
    if (ctx) BN_CTX_free(ctx);
    return 0;
}