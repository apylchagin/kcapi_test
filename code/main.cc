#include <gtest/gtest.h>
#include <kcapi.h>
#include <openssl/aes.h>
#include <vector>
#include <cstdint>
#include <cstring>

TEST(EncDec,  KcapiEncDec) {
	uint8_t key[16] = { 0 };
	uint8_t data[88000] = { 0 };
	uint8_t data2[88000] = { 1 };
	uint8_t ct[88000];
	const uint8_t iv[16] = { 0 };

	ASSERT_EQ(0, sizeof(data) % 16);

	ASSERT_EQ(sizeof(data), kcapi_cipher_enc_aes_cbc(key, sizeof(key),
				 data, sizeof(data),
				 iv,
				 ct, sizeof(ct)));
	ASSERT_EQ(sizeof(ct), kcapi_cipher_dec_aes_cbc(key, sizeof(key),
				 ct, sizeof(ct),
				 iv,
				 data2, sizeof(data2)));
        ASSERT_EQ(std::vector<uint8_t>(data, data + sizeof(data)),
                  std::vector<uint8_t>(data2, data2 + sizeof(data2)));
}

TEST(EncDec, OpenSSLEncDec) {
        const uint8_t key[16] = { 0 };
        uint8_t data[88000] = { 0 };
        uint8_t data2[88000] = { 1 };
        uint8_t ct[88000];

        ASSERT_EQ(0, sizeof(data) % 16);
	memset(data2, 0xf1, sizeof(data2));
	{
        	uint8_t iv[16] = { 0 };
        	AES_KEY aes_ks;
        	ASSERT_EQ(0, AES_set_encrypt_key(key, 128, &aes_ks));
        	AES_cbc_encrypt(data, ct, sizeof(data), &aes_ks, iv, AES_ENCRYPT);
	}
	{
	        uint8_t iv[16] = { 0 };
                AES_KEY aes_ks;
                ASSERT_EQ(0, AES_set_decrypt_key(key, 128, &aes_ks));
                AES_cbc_encrypt(ct, data2, sizeof(ct), &aes_ks, iv, AES_DECRYPT);
	}
        ASSERT_EQ(std::vector<uint8_t>(data, data + sizeof(data)),
                  std::vector<uint8_t>(data2, data2 + sizeof(data2)));
}

TEST(EncDec, KcapiEncOpenSSLDec) {
        uint8_t key[16] = { 0 };
        uint8_t data[88000] = { 0 };
        uint8_t data2[88000] = { 1 };
        uint8_t ct[88000];
        uint8_t iv[16] = { 0 };

	memset(data2, 0xf1, sizeof(data2));

        ASSERT_EQ(0, sizeof(data) % 16);

        ASSERT_EQ(sizeof(data), kcapi_cipher_enc_aes_cbc(key, sizeof(key),
                                 data, sizeof(data),
                                 iv,
                                 ct, sizeof(ct)));
        for (size_t idx = 0; idx < sizeof(iv); ++idx) {
            ASSERT_EQ(0, iv[idx]);
        }
	{
        	AES_KEY aes_ks;
        	ASSERT_EQ(0, AES_set_decrypt_key(key, 128, &aes_ks));
        	AES_cbc_encrypt(ct, data2, sizeof(ct), &aes_ks, iv, AES_DECRYPT);
	}
        EXPECT_EQ(std::vector<uint8_t>(data, data + sizeof(data)),
                  std::vector<uint8_t>(data2, data2 + sizeof(data2)));
        for (size_t idx = 0; idx < sizeof(data); ++idx) {
		EXPECT_EQ(data[idx], data2[idx]) << "idx==" << idx << " of " << sizeof(data);
        }
}

TEST(EncDec, OpenSSLEncKcapiDec) {
        const uint8_t key[16] = { 0 };
        uint8_t data[88000] = { 0 };
        uint8_t data2[88000] = { 1 };
        uint8_t ct[88000];

        ASSERT_EQ(0, sizeof(data) % 16);
        memset(data2, 0xf1, sizeof(data2));
        {
                uint8_t iv[16] = { 0 };
                AES_KEY aes_ks;
                ASSERT_EQ(0, AES_set_encrypt_key(key, 128, &aes_ks));
                AES_cbc_encrypt(data, ct, sizeof(data), &aes_ks, iv, AES_ENCRYPT);
        }
        {
                const uint8_t iv[16] = { 0 };
	        ASSERT_EQ(sizeof(ct), kcapi_cipher_dec_aes_cbc(key, sizeof(key),
	                                 ct, sizeof(ct),
	                                 iv,
	                                 data2, sizeof(data2)));

        }
        EXPECT_EQ(std::vector<uint8_t>(data, data + sizeof(data)),
                  std::vector<uint8_t>(data2, data2 + sizeof(data2)));
        for (size_t idx = 0; idx < sizeof(data); ++idx) {
                EXPECT_EQ(data[idx], data2[idx]) << "idx==" << idx << " of " << sizeof(data);
        }


}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    const auto rc = RUN_ALL_TESTS();
    return rc;
}
