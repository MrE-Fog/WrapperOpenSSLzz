#include "algorithmsha256.h"

#include <iostream>
#include <iomanip>

#include <cstring>
#include <cstdio>

namespace OCF
{

AlgorithmSHA256::AlgorithmSHA256()
{
}

void AlgorithmSHA256::InitAlgorythm()
{
    SHA256_Init( &c );
    memset( sha256, 0, sizeof( sha256 ) );
}

bool AlgorithmSHA256::UpdateAlgorythm(int len, const char *data)
{
    // Update sum
    if( len <= 0 )
    {
//        close( fd );
//        fd = -1;
        SHA256_Final( sha256, &c );

        char code[3];
        for( int i = 0; i < SHA256_DIGEST_LENGTH; i++ )
        {
            sprintf( code, "%x%x", (sha256[i] & 0xF0)/16, (sha256[i] & 0x0F) );
            sha256sum[i*2] = code[0];
            sha256sum[i*2+1] = code[1];
        }
        sha256sum[SHA256_DIGEST_LENGTH*2] = 0;

        if(m_verbose)
        {
            std::cout << "Authenticator_SHA256_file calculated: " << sha256sum << std::endl;
        }

        return true;
    }
    SHA256_Update( &c, data, len );
    return false;
}

void AlgorithmSHA256::FillAlgorythmResult(tAuth_Result&m_native_data)
{
    m_native_data.auth_len = 32;
    for(size_t i=0; i<m_native_data.auth_len ; ++i )
        m_native_data.auth_data[i] = sha256[i];
}

}
