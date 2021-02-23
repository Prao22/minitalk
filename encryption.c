#include "encryption.h"

int encode_AES(unsigned char aes_iv[], unsigned char aes_key[], char *plain_text, unsigned char *encrypted)
{
    bool no_err = true;
    int encrypted_len = 0;
    int temp_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    RAND_bytes(aes_key, AES_KEY_LEN);
    RAND_bytes(aes_iv, AES_IV_LEN);

    no_err = EVP_EncryptInit(ctx, EVP_aes_256_cbc(), aes_key, aes_iv);
    EVP_CIPHER_CTX_set_padding(ctx, 1); // returns always 1

    if(no_err) 
    {
        no_err = EVP_EncryptUpdate(ctx, encrypted, &temp_len, (unsigned char *)plain_text, strlen(plain_text) + 1);
        encrypted_len += temp_len;
    }

    if (no_err)
    {
        no_err = EVP_EncryptFinal(ctx, encrypted + encrypted_len, &temp_len);
        encrypted_len += temp_len;
    }

    EVP_CIPHER_CTX_free(ctx);

    if(!no_err)
    {
        show_openssl_err();
        return -1;
    }

    return encrypted_len;
}

int decode_AES(unsigned char aes_iv[], unsigned char aes_key[], unsigned char *encrypted, int encrypted_len, char *plain_text)
{
    bool no_err = true;
    int temp_len = 0;
    int decrypted_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    no_err = EVP_DecryptInit(ctx, EVP_aes_256_cbc(), aes_key, aes_iv);
    EVP_CIPHER_CTX_set_padding(ctx, 1); // returns always 1

    if (no_err)
    {
        no_err = EVP_DecryptUpdate(ctx, (unsigned char *)plain_text, &temp_len, encrypted, encrypted_len);
        decrypted_len += temp_len;
    }

    if (no_err)
    {
        no_err = EVP_DecryptFinal(ctx, (unsigned char *)(plain_text + temp_len), &temp_len);
        decrypted_len += temp_len;
    }    

    EVP_CIPHER_CTX_free(ctx);

    if(!no_err)
    {
        show_openssl_err();
        return -1;
    }

    return decrypted_len;
}

int decrypt_message(unsigned char *encrypted, int size, char *login, char *plain_text, RSA* keys)
{
    unsigned char loginandkey[AES_KEY_LEN + MAX_LOGIN];
    unsigned char aes_key[AES_KEY_LEN];
    unsigned char aes_iv[AES_IV_LEN];

    memcpy(aes_iv, encrypted, AES_IV_LEN);

    if (RSA_private_decrypt(RSA_ENCRYPTED_LEN, encrypted + AES_IV_LEN, loginandkey, keys, RSA_PKCS1_PADDING) == -1)
    {
        show_openssl_err();
        return -1;
    }

    memcpy(login, loginandkey, MAX_LOGIN);
    memcpy(aes_key, loginandkey + MAX_LOGIN, AES_KEY_LEN);

    return decode_AES(aes_iv, aes_key, encrypted + RSA_ENCRYPTED_LEN + AES_IV_LEN, size - AES_IV_LEN - RSA_ENCRYPTED_LEN, plain_text);
}

int encrypt_message(char *plain_text, char *login, unsigned char *encrypted, RSA *keys)
{
    unsigned char aes_key[AES_KEY_LEN];
    unsigned char aes_iv[AES_IV_LEN];
    unsigned char encrypted_text[strlen(plain_text) + 1 + AES_BLOCK_SIZE];
    int aes_len = encode_AES(aes_iv, aes_key, plain_text, encrypted_text);

    if (aes_len == -1)
    {
        show_openssl_err();
        return -1;
    }

    memcpy(encrypted, aes_iv, AES_IV_LEN);

    unsigned char loginandkey[MAX_LOGIN + AES_KEY_LEN];
    memcpy(loginandkey, login, strlen(login) + 1);
    memcpy(loginandkey + MAX_LOGIN, aes_key, AES_KEY_LEN);

    int rsa_length = RSA_public_encrypt(MAX_LOGIN + AES_KEY_LEN, loginandkey, encrypted + AES_IV_LEN, keys, RSA_PKCS1_PADDING);

    if (rsa_length < 1)
    {
        show_openssl_err();
        return -1;
    }

    memcpy(encrypted + rsa_length + AES_IV_LEN, encrypted_text, aes_len);

    return rsa_length + AES_IV_LEN + aes_len;
}


int create_RSA(RSA** keys)
{
    *keys = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);
    RAND_load_file("/dev/urandom", 2048);

    int result = RSA_generate_key_ex(*keys, RSA_BITS, e, NULL);

    BN_free(e);
    return result;
}

void delete_RSA(RSA** keys)
{
    RSA_free(*keys);
    *keys = NULL;
}


int send_public_RSA(RSA* keys, int fd)
{
    BIO *bufio;
    bufio = BIO_new_fd(fd, 0);
    int result = PEM_write_bio_RSAPublicKey(bufio, keys); // 1 - success
    BIO_free(bufio);
    return !result;
}

int read_public_RSA(RSA** keys, int fd)
{
    BIO *bufio;
    bufio = BIO_new_fd(fd, 0);
    void *ret = PEM_read_bio_RSAPublicKey(bufio, keys, 0, NULL);
    BIO_free(bufio);
    return ret == NULL;
}


void print_RSA(RSA *keys)
{
    BIO *bio = BIO_new_fd(2, 0);
    RSA_print(bio, keys, 0);
    BIO_free(bio);
}

void print_bytes(unsigned char *bytes, int size)
{
    fprintf(stderr, "\n--------------\n");

    int i = 0;
    for (; i < (size / 16); i++)
    {
        for (int j = 0; j < 16; j++)
        {
            fprintf(stderr, "%x:", bytes[16 * i + j]);
        }

        fprintf(stderr, "\n");
    }

    for (int j = 0; j < size % 16; j++)
    {
        fprintf(stderr, "%x:", bytes[16 * i + j]);
    }

    fprintf(stderr, "\n--------------\n");
}

int show_openssl_err()
{
    unsigned long err = ERR_get_error();
    fprintf(stderr, "\nERROR -> : %ld\n%s\n", err, ERR_error_string(err, NULL));
    return err;
}
