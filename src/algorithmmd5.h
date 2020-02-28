#ifndef ALGORITHMMD5_H
#define ALGORITHMMD5_H

#include "algorithm.h"

namespace OCF
{

class AlgorithmMD5 : public Algorithm
{
public:
    AlgorithmMD5();

    void InitAlgorythm() override;
    bool UpdateAlgorythm(int read_len, const char *data) override;
    void FillAlgorythmResult(tAuth_Result &m_native_data) override;

private:
    MD5_CTX c;
    unsigned char   md[16];
    char			md5sum[33];

};

}
#endif // ALGORITHMMD5_H
