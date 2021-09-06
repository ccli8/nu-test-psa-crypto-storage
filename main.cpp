#include "mbed.h"
#include "unity/unity.h"
#include "psa/crypto.h"

static void test_generate_volatile_key(void);
static void test_generate_persistent_key(void);

int main()
{
    //UnityBegin(__FILE__);
    UNITY_BEGIN();

    test_generate_volatile_key();
    test_generate_persistent_key();

    while (1);

}

/* TEST: Generate volatile key with psa_generate_key */
static void test_generate_volatile_key(void)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    
    status = psa_crypto_init();
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);

    status = psa_generate_key(&attributes, &key_id);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
    printf("Volatile key_id=0x%08x\r\n", key_id);
}

/* TEST: Generate persistent key with psa_generate_key */
static void test_generate_persistent_key(void)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    
    status = psa_crypto_init();
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_id(&attributes, PSA_KEY_ID_USER_MIN);

    status = psa_generate_key(&attributes, &key_id);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
    printf("Persistent key_id=0x%08x\r\n", key_id);
    TEST_ASSERT_EQUAL(PSA_KEY_ID_USER_MIN, key_id);
}
