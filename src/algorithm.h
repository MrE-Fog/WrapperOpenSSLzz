#ifndef ALGORITHM_H
#define ALGORITHM_H

#include "authcomponent.h"

#include <openssl/md5.h>
#include <openssl/sha.h>

namespace OCF
{

enum class CheckSumMode
{
    MD5 = 1,
    SHA1,
    SHA256,
    SHA1_HMAC
};

class Algorithm;
using PtrAlgorithm = std::shared_ptr<Algorithm>;

class Algorithm
{
public:
    virtual void InitAlgorythm() = 0;
    virtual bool UpdateAlgorythm(int read_len, const char *data) = 0;
    virtual void FillAlgorythmResult(tAuth_Result &m_native_data) = 0;
    virtual void setHMACParams(int keyLength, const char* key, unsigned int tag_len = 20);

protected:
    bool m_verbose = false;
};

}

//using PtrAlgorithm = Algorithm *;//std::shared_ptr<Algorithm>;



#endif // ALGORITHM_H
