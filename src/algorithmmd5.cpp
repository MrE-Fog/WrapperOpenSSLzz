#include "algorithmmd5.h"

#include <iostream>
#include <cstring>
#include <iostream>
#include <iomanip>

namespace OCF
{

AlgorithmMD5::AlgorithmMD5()
{
}

void AlgorithmMD5::InitAlgorythm()
{
    MD5_Init( &c );
    memset( md, 0, sizeof( md ) );
}

bool AlgorithmMD5::UpdateAlgorythm(int len, const char *data)
{
    // Update sum
    if( len <= 0 )
    {
//        close( fd );
//        fd = -1;
        MD5_Final( md, &c );

        char code[3];
        for( int i = 0; i < 16; i++ )
        {
            sprintf( code, "%x%x", (md[i] & 0xF0)/16, (md[i] & 0x0F) );
            md5sum[i*2] = code[0];
            md5sum[i*2+1] = code[1];
        }
        md5sum[32]=0;
        if(m_verbose)
        {
            std::cout << "Authenticator_MD5_file calculated: " << md5sum << std::endl;
        }

        return true;
    }
    MD5_Update( &c, data, len );
    return false;
}

void AlgorithmMD5::FillAlgorythmResult(tAuth_Result& m_native_data)
{
    m_native_data.auth_len = 16;

    if(m_verbose)
        std::cout << "NativeData:" << std::endl;

    for(size_t i=0; i<m_native_data.auth_len ; ++i )
    {
        m_native_data.auth_data[i] = md[i];

        if(m_verbose)
            std::cout << std::hex << std::setw(2) << std::setfill('0') <<int(m_native_data.auth_data[i])  << std::dec << std::flush;
    }

    if(m_verbose)
        std::cout << std::endl;
}

}
