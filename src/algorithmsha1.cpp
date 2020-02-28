#include "algorithmsha1.h"

#include <iostream>
#include <iomanip>

#include <cstring>
#include <cstdio>

namespace OCF
{

AlgorithmSHA1::AlgorithmSHA1()
{
}

void AlgorithmSHA1::InitAlgorythm()
{
    SHA1_Init( &c );
    memset( sha1, 0, sizeof( sha1 ) );
}

bool AlgorithmSHA1::UpdateAlgorythm(int len, const char *data)
{
    // Update sum
    if( len <= 0 )
    {
//        close( fd );
//        fd = -1;
        SHA1_Final( sha1, &c );

        char code[3];
        for( int i = 0; i < 20; i++ )
        {
            sprintf( code, "%x%x", (sha1[i] & 0xF0)/16, (sha1[i] & 0x0F) );
            sha1sum[i*2] = code[0];
            sha1sum[i*2+1] = code[1];
        }
        sha1sum[40]=0;

        if(m_verbose)
        {
            std::cout << "Authenticator_SHA1_file calculated: " << sha1sum << std::endl;
        }

        return true;
    }
    SHA1_Update( &c, data, len );
    return false;
}

void AlgorithmSHA1::FillAlgorythmResult(tAuth_Result &m_native_data)
{
    m_native_data.auth_len = 20;

    for(size_t i=0; i<m_native_data.auth_len ; ++i )
        m_native_data.auth_data[i] = sha1[i];
}

}
