#pragma once

#ifndef ALGORITHMBUILDER_H
#define ALGORITHMBUILDER_H

#include "algorithmmd5.h"
#include "algorithmsha1_hmac.h"
#include "algorithmsha1.h"
#include "algorithmsha256.h"

namespace OCF
{

class AlgorithmBuilder
{
public:    
    static PtrAlgorithm factoryAlgorithm(CheckSumMode mode);
};

}

#endif // ALGORITHMBUILDER_H
