#include <jni.h>
#include <string>
#include <android/log.h>
#include <malloc.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/sms4.h>
#include <crypto/ec/ec_lcl.h>
#include <openssl/aes.h>



#define LOG_TAG "younger"
#define LOGIO(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)

EC_KEY *setSm2PrivateKey(char* privatekey){
    EC_KEY *ec_key = EC_KEY_new();
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    BIGNUM *x = BN_new();
    int iret = BN_hex2bn(&x, privatekey);
    iret = EC_KEY_set_private_key(ec_key, x);
    BN_free(x);
    return ec_key;
}

EC_KEY *setSm2PublicKey(char* keyA, char* keyB) {
    EC_KEY *ec_key = EC_KEY_new();
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);

    BIGNUM *x = BN_new();
    int iret = BN_hex2bn(&x, keyA);
    BIGNUM *y = BN_new();
    iret = BN_hex2bn(&y, keyB);
    iret = EC_KEY_set_public_key_affine_coordinates(ec_key, x, y);
    //__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "setSm2PublicKey:%d", iret);

    BN_free(x);
    BN_free(y);
    return ec_key;
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_younger_gmssl_Crypto_aesEnc(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {

    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    int pading = AES_BLOCK_SIZE - length % AES_BLOCK_SIZE;
    int block = length / AES_BLOCK_SIZE;
    int endLen = AES_BLOCK_SIZE - pading;

    unsigned char *p = (unsigned char *) malloc(AES_BLOCK_SIZE + 1);
    memset(p, 0, AES_BLOCK_SIZE + 1);
    memset(p + endLen, pading, (size_t) pading);
    memcpy(p, in + block * AES_BLOCK_SIZE, (size_t) endLen);

    AES_KEY aes_key;
    AES_set_encrypt_key((const unsigned char *) key, 16 * 8, &aes_key);

    unsigned char *out = (unsigned char *) malloc((size_t) (length + pading + 1));
    memset(out, 0, (size_t) (length + pading + 1));

    for (int i = 0; i < block; i++) {
        AES_encrypt((const unsigned char *) (in + (i * AES_BLOCK_SIZE)),
                    out + i * AES_BLOCK_SIZE,
                    &aes_key);
    }
    AES_encrypt(p, out + block * AES_BLOCK_SIZE, &aes_key);

    jbyteArray array = env->NewByteArray(length + pading);
    env->SetByteArrayRegion(array, 0, length + pading, (const jbyte *) out);

    free(p);
    free(out);

    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;


}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_younger_gmssl_Crypto_aesDec(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    AES_KEY aes_key;
    AES_set_decrypt_key((const unsigned char *) key, 16 * 8, &aes_key);

    unsigned char *out = (unsigned char *) malloc(length);
    memset(out, 0, length);

    for (int i = 0; i < length / 16; i++) {
        AES_decrypt((const unsigned char *) (in + (i * AES_BLOCK_SIZE)),
                    out + i * AES_BLOCK_SIZE,
                    &aes_key);
    }
    //去补位
    int padinglen = out[length - 1];
    memset(out + length - padinglen, 0, padinglen);

    jbyteArray array = env->NewByteArray(length - padinglen);
    env->SetByteArrayRegion(array, 0, length - padinglen, (const jbyte *) out);

    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_younger_gmssl_Crypto_sm4Enc(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    int pading = SMS4_KEY_LENGTH - length % SMS4_KEY_LENGTH;
    int block = length / SMS4_KEY_LENGTH;
    int endLen = SMS4_KEY_LENGTH - pading;

    unsigned char *p = (unsigned char *) malloc(SMS4_KEY_LENGTH + 1);
    memset(p, 0, SMS4_KEY_LENGTH + 1);
    memset(p + endLen, pading, (size_t) pading);
    memcpy(p, in + block * SMS4_KEY_LENGTH, (size_t) endLen);

    sms4_key_t sms4EncKey;
    sms4_set_encrypt_key(&sms4EncKey, (const unsigned char *) key);

    unsigned char *out = (unsigned char *) malloc((size_t) (length + pading + 1));
    memset(out, 0, (size_t) (length + pading + 1));

    for (int i = 0; i < block; i++) {
        sms4_encrypt((const unsigned char *) (in + (i * 16)), out + i * 16, &sms4EncKey);
    }
    sms4_encrypt(p, out + block * 16, &sms4EncKey);

    jbyteArray array = env->NewByteArray(length + pading);
    env->SetByteArrayRegion(array, 0, length + pading, (const jbyte *) out);

    free(p);
    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_younger_gmssl_Crypto_sm4Dec(JNIEnv *env, jobject instance, jbyteArray in_, jint length,
                                   jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    sms4_key_t sms4DecKey;
    sms4_set_decrypt_key(&sms4DecKey, (const unsigned char *) key);

    unsigned char *out = (unsigned char *) malloc(length);
    memset(out, 0, length);

    for (int i = 0; i < length / 16; i++) {
        sms4_decrypt((const unsigned char *) (in + (i * 16)), out + i * 16, &sms4DecKey);
    }
    //去补位
    int padinglen = out[length - 1];
    memset(out + length - padinglen, 0, padinglen);

    jbyteArray array = env->NewByteArray(length - padinglen);
    env->SetByteArrayRegion(array, 0, length - padinglen, (const jbyte *) out);

    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_younger_gmssl_Crypto_sm2Enc(JNIEnv *env, jobject instance, jbyteArray in_, jint length, jbyteArray keya_, jbyteArray keyb_) {

    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *keya = env->GetByteArrayElements(keya_, NULL);
    int len_keyA = env->GetArrayLength(keya_);

    jbyte *keyb = env->GetByteArrayElements(keyb_, NULL);
    int len_keyB = env->GetArrayLength(keyb_);


    char* ykeyA = new char[len_keyA + 1];
    memset(ykeyA, NULL, len_keyA + 1);
    memcpy(ykeyA, keya, len_keyA);

    char* ykeyB = new char[len_keyB + 1];
    memset(ykeyB, NULL, len_keyB + 1);
    memcpy(ykeyB, keyb, len_keyB);


    int iRet = 0;
    EC_KEY *ec_key = setSm2PublicKey((char *)ykeyA, (char *)ykeyB);
    size_t sm2EncLen = length + 200;


    unsigned char *sm2EncMsg = (unsigned char *) malloc(sm2EncLen);
    memset(sm2EncMsg, 0, sm2EncLen);
    iRet = SM2_encrypt_with_recommended((const unsigned char *) in,
                                        (size_t) length,
                                        sm2EncMsg,
                                        &sm2EncLen,
                                        ec_key);
    //__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Java_com_aisi_crypto_Crypto_sm2Enc %d", iRet);
    if (1 != iRet) {
        ERR_load_ERR_strings();
        ERR_load_crypto_strings();

        unsigned long ulErr = ERR_get_error(); // 获取错误号
        //__android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Java_com_aisi_crypto_Crypto_sm2Enc %d", iRet);
        const char *pTmp = ERR_reason_error_string(ulErr);
        puts(pTmp);
    }

    jbyteArray array = env->NewByteArray(sm2EncLen);
    env->SetByteArrayRegion(array, 0, sm2EncLen, (const jbyte *) sm2EncMsg);

    free(sm2EncMsg);
    EC_KEY_free(ec_key);

    delete ykeyA;
    delete ykeyB;

    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(keya_, keya, 0);
    env->ReleaseByteArrayElements(keyb_, keyb, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_younger_gmssl_Crypto_sm2Dec(JNIEnv *env, jobject instance, jbyteArray in_, jint length, jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    int iRet = 0;
    EC_KEY *ec_key = setSm2PrivateKey((char *)key);
    size_t sm2DecLen = 0;

    iRet = SM2_decrypt(NID_sm3,
                       (const unsigned char *) in,
                       (size_t) length,
                       NULL,
                       &sm2DecLen,
                       ec_key);

    unsigned char *sm2DecMsg = (unsigned char *) malloc(sm2DecLen + 1);
    memset(sm2DecMsg, 0, sm2DecLen);

    iRet = SM2_decrypt(NID_sm3,
                       (const unsigned char *) in,
                       (size_t) length,
                       sm2DecMsg,
                       &sm2DecLen,
                       ec_key);

    jbyteArray array = env->NewByteArray(sm2DecLen);
    env->SetByteArrayRegion(array, 0, sm2DecLen, (const jbyte *) sm2DecMsg);

    free(sm2DecMsg);
    EC_KEY_free(ec_key);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}