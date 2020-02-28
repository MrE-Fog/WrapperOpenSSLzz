#ifndef ALGORITHMSHA1_H
#define ALGORITHMSHA1_H

#include "algorithm.h"

namespace OCF
{

class AlgorithmSHA1 : public Algorithm
{
public:
    AlgorithmSHA1();

    void InitAlgorythm() override;
    bool UpdateAlgorythm(int read_len, const char *data) override;
    void FillAlgorythmResult(tAuth_Result &m_native_data) override;

private:
    SHA_CTX c;
    unsigned char   sha1[20];
    char			sha1sum[41];

};

}
#endif // ALGORITHMSHA1_H
