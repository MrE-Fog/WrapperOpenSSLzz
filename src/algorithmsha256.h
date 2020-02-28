#ifndef ALGORITHMSHA256_H
#define ALGORITHMSHA256_H

#include "algorithm.h"

namespace OCF
{

class AlgorithmSHA256 : public Algorithm
{
public:
    AlgorithmSHA256();

    void InitAlgorythm() override;
    bool UpdateAlgorythm(int read_len, const char *data) override;
    void FillAlgorythmResult(tAuth_Result &m_native_data) override;

private:
    SHA256_CTX c;
    unsigned char   sha256[SHA256_DIGEST_LENGTH];
    char            sha256sum[SHA256_DIGEST_LENGTH*2+1];

};

}

#endif // ALGORITHMSHA256_H
