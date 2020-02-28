#ifndef ALGORITHMSHA1_HMAC_H
#define ALGORITHMSHA1_HMAC_H

#include "algorithm.h"

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

namespace OCF
{

class AlgorithmSHA1_HMAC : public Algorithm
{
public:
    AlgorithmSHA1_HMAC();

    void InitAlgorythm() override;
    bool UpdateAlgorythm(int len, const char *data) override;
    void FillAlgorythmResult(tAuth_Result &m_native_data) override;

    void setHMACParams(int keyLength, const char* key, unsigned int tag_len = 20) override;

private:
    const static int MAX_SIZE_KEY = 128;

    HMAC_CTX ctx;

    //unsigned int res_len;
    unsigned int tag_len;

    int key_len;
    unsigned char   key[MAX_SIZE_KEY];

    unsigned char   sha1[MAX_SIZE_KEY];
    char			sha1sum[MAX_SIZE_KEY];
};

}

#endif // ALGORITHMSHA1_HMAC_H
