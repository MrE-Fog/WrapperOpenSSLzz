#include "algorithmsha1_hmac.h"

#include <iostream>
#include <vector>
#include <cstring>

namespace OCF
{

unsigned char getNumbFromHex(unsigned char ch1)
{
	unsigned char num = 0;

	if (('a' <= ch1) && (ch1 <= 'f'))
	{
		num = 10 + ch1 - 0x61;
	}
	else
		if (('A' <= ch1) && (ch1 <= 'F'))
		{
			num = 10 + ch1 - 0x41;
		}
		else
	{
		num = ch1 - 48;
	}

	return num;
}


void convertHexToNumber(int len, const unsigned char *data, std::vector<unsigned char> &result)
{
    if((len <= 0) || ((len % 2) != 0))
    {
        std::cout << "Error convertHexToNumber (len must be even) len=" << len << std::endl;
        return;
    }

    for (int iii = 0; iii < len; iii += 2)
    {
        unsigned char num1 = getNumbFromHex(data[iii + 1]);
        num1 = num1 + 16*getNumbFromHex(data[iii]);
        result.push_back(num1);
    }
}

AlgorithmSHA1_HMAC::AlgorithmSHA1_HMAC():
    tag_len{20},
    key_len{0},
    key{},
    sha1{},
    sha1sum{}
{
}

void AlgorithmSHA1_HMAC::InitAlgorythm()
{
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, key_len, EVP_sha1(), NULL);
}

bool AlgorithmSHA1_HMAC::UpdateAlgorythm(int len, const char* data)
{
    // Update sum
    if( len <= 0 )
    {
        unsigned int tag_len1 = 0;
        HMAC_Final(&ctx, sha1, &tag_len1);

        char code[3];
        for(unsigned int i = 0; i < tag_len; i++ )
        {
            sprintf( code, "%x%x", (sha1[i] & 0xF0)/16, (sha1[i] & 0x0F) );
            sha1sum[i*2]    = code[0];
            sha1sum[i*2+1]  = code[1];
        }
        //sha1sum[40]=0;

        if(m_verbose)
        {
            std::cout << "Authenticator_SHA1_HMAC calculated: " << sha1sum << std::endl;
        }
        return true;
    }

    HMAC_Update(&ctx, (const unsigned char*)data, len);
    return false;
}

void AlgorithmSHA1_HMAC::FillAlgorythmResult(tAuth_Result& m_native_data)
{
    m_native_data.auth_len = tag_len;

    for(size_t i=0; i<m_native_data.auth_len ; ++i)
    {
        m_native_data.auth_data[i] = sha1[i];
    }
}

void AlgorithmSHA1_HMAC::setHMACParams(int keyLength, const char* key, unsigned int tag_len)
{
    this->tag_len = tag_len;

    if(keyLength > MAX_SIZE_KEY)
    {
        std::cout << "Error AlgorithmSHA1_HMAC::setHMACParams key length more than max" << keyLength << std::endl;
        return;
    }

    std::vector<unsigned char> vect1;

    convertHexToNumber(2*keyLength, (const unsigned char *)key, vect1);

    key_len = vect1.size();
    memcpy(this->key, vect1.data(), key_len);
}

}
