int generate_pubkey_hash_from_privkey(const unsigned char *priv_key_bytes, unsigned char *pubkey_hash_out);
int base58_decode_bitcoin_address(const char *base58_addr, unsigned char *pubkey_hash_out);
int decode_wif(const char *wif, unsigned char *priv_key_out, int *compressed_out);
