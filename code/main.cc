#include <gtest/gtest.h>
#include <kcapi.h>
#include <openssl/aes.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <unistd.h>

static const size_t KCAPI_PAGE_SIZE = sysconf(_SC_PAGESIZE);
static const size_t KCAPI_TEST_SIZE = 88000;

static uint8_t* allocate_aligned(size_t size) {
    void* rc = nullptr;
    if (posix_memalign(&rc, KCAPI_PAGE_SIZE, size) == 0) {
        return static_cast<uint8_t*>(rc);
    }
    return nullptr;
}

TEST(EncDec,  KcapiEncDec) {
	uint8_t key[16] = { 0 };
	uint8_t *data = allocate_aligned(KCAPI_TEST_SIZE);
	uint8_t *data2 = allocate_aligned(KCAPI_TEST_SIZE);
	uint8_t *ct =  allocate_aligned(KCAPI_TEST_SIZE);
	const uint8_t iv[16] = { 0 };

	ASSERT_EQ(0, KCAPI_TEST_SIZE % 16);
	ASSERT_EQ(KCAPI_TEST_SIZE, kcapi_cipher_enc_aes_cbc(key, sizeof(key),
				 data, KCAPI_TEST_SIZE,
				 iv,
				 ct, KCAPI_TEST_SIZE));
	ASSERT_EQ(KCAPI_TEST_SIZE, kcapi_cipher_dec_aes_cbc(key, sizeof(key),
				 ct, KCAPI_TEST_SIZE,
				 iv,
				 data2, KCAPI_TEST_SIZE));
        ASSERT_EQ(std::vector<uint8_t>(data, data + KCAPI_TEST_SIZE),
                  std::vector<uint8_t>(data2, data2 + KCAPI_TEST_SIZE));
        free(data);
        free(data2);
        free(ct);
}

TEST(EncDec, OpenSSLEncDec) {
        const uint8_t key[16] = { 0 };
        uint8_t *data = allocate_aligned(KCAPI_TEST_SIZE);
        uint8_t *data2 = allocate_aligned(KCAPI_TEST_SIZE);
        uint8_t *ct =  allocate_aligned(KCAPI_TEST_SIZE);

        ASSERT_EQ(0, KCAPI_TEST_SIZE % 16);
	memset(data2, 0xf1, KCAPI_TEST_SIZE);
	{
        	uint8_t iv[16] = { 0 };
        	AES_KEY aes_ks;
        	ASSERT_EQ(0, AES_set_encrypt_key(key, 128, &aes_ks));
        	AES_cbc_encrypt(data, ct, KCAPI_TEST_SIZE, &aes_ks, iv, AES_ENCRYPT);
	}
	{
	        uint8_t iv[16] = { 0 };
                AES_KEY aes_ks;
                ASSERT_EQ(0, AES_set_decrypt_key(key, 128, &aes_ks));
                AES_cbc_encrypt(ct, data2, KCAPI_TEST_SIZE, &aes_ks, iv, AES_DECRYPT);
	}
        ASSERT_EQ(std::vector<uint8_t>(data, data + KCAPI_TEST_SIZE),
                  std::vector<uint8_t>(data2, data2 + KCAPI_TEST_SIZE));
        free(data);
        free(data2);
        free(ct);
}

TEST(EncDec, KcapiEncOpenSSLDec) {
        uint8_t key[16] = { 0 };
        uint8_t iv[16] = { 0 };
        uint8_t *data = allocate_aligned(KCAPI_TEST_SIZE);
        uint8_t *data2 = allocate_aligned(KCAPI_TEST_SIZE);
        uint8_t *ct =  allocate_aligned(KCAPI_TEST_SIZE);

	memset(data2, 0xf1, KCAPI_TEST_SIZE);

        ASSERT_EQ(0, KCAPI_TEST_SIZE % 16);

        ASSERT_EQ(KCAPI_TEST_SIZE, kcapi_cipher_enc_aes_cbc(key, sizeof(key),
                                 data, KCAPI_TEST_SIZE,
                                 iv,
                                 ct, KCAPI_TEST_SIZE));
        for (size_t idx = 0; idx < sizeof(iv); ++idx) {
            ASSERT_EQ(0, iv[idx]);
        }
	{
        	AES_KEY aes_ks;
        	ASSERT_EQ(0, AES_set_decrypt_key(key, 128, &aes_ks));
        	AES_cbc_encrypt(ct, data2, KCAPI_TEST_SIZE, &aes_ks, iv, AES_DECRYPT);
	}
        EXPECT_EQ(std::vector<uint8_t>(data, data + KCAPI_TEST_SIZE),
                  std::vector<uint8_t>(data2, data2 + KCAPI_TEST_SIZE));
        for (size_t idx = 0; idx < KCAPI_TEST_SIZE; ++idx) {
		EXPECT_EQ(data[idx], data2[idx]) << "idx==" << idx << " of " << KCAPI_TEST_SIZE;
        }
        free(data);
        free(data2);
        free(ct);
}

TEST(EncDec, OpenSSLEncKcapiDec) {
        const uint8_t key[16] = { 0 };
        uint8_t *data = allocate_aligned(KCAPI_TEST_SIZE);
        uint8_t *data2 = allocate_aligned(KCAPI_TEST_SIZE);
        uint8_t *ct =  allocate_aligned(KCAPI_TEST_SIZE);

        ASSERT_EQ(0, KCAPI_TEST_SIZE % 16);
        memset(data2, 0xf1, KCAPI_TEST_SIZE);
        {
                uint8_t iv[16] = { 0 };
                AES_KEY aes_ks;
                ASSERT_EQ(0, AES_set_encrypt_key(key, 128, &aes_ks));
                AES_cbc_encrypt(data, ct, KCAPI_TEST_SIZE, &aes_ks, iv, AES_ENCRYPT);
        }
        {
                const uint8_t iv[16] = { 0 };
	        ASSERT_EQ(KCAPI_TEST_SIZE, kcapi_cipher_dec_aes_cbc(key, sizeof(key),
	                                 ct, KCAPI_TEST_SIZE,
	                                 iv,
	                                 data2, KCAPI_TEST_SIZE));

        }
        EXPECT_EQ(std::vector<uint8_t>(data, data + KCAPI_TEST_SIZE),
                  std::vector<uint8_t>(data2, data2 + KCAPI_TEST_SIZE));
        for (size_t idx = 0; idx < KCAPI_TEST_SIZE; ++idx) {
                EXPECT_EQ(data[idx], data2[idx]) << "idx==" << idx << " of " << KCAPI_TEST_SIZE;
        }

        free(data);
        free(data2);
        free(ct);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    const auto rc = RUN_ALL_TESTS();
    return rc;
}
