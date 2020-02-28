#include "algorithmbuilder.h"

namespace OCF
{

PtrAlgorithm AlgorithmBuilder::factoryAlgorithm(CheckSumMode mode)
{
    switch(mode)
    {
        case CheckSumMode::MD5:
            return std::make_shared<AlgorithmMD5>();
        break;
        case CheckSumMode::SHA1:
            return std::make_shared<AlgorithmSHA1>();
        break;
        case CheckSumMode::SHA256:
            return std::make_shared<AlgorithmSHA256>();
        break;
        case CheckSumMode::SHA1_HMAC:
            return std::make_shared<AlgorithmSHA1_HMAC>();
        break;
    }
    return nullptr;
}

}
