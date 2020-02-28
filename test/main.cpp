#include <iostream>
#include <memory>
#include <vector>

#include "checksum.h"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <cstring>

using namespace OCF;

int main(int /*argc*/, char** /* *argv[] */)
{
    std::cout << "Test checksum OCF" << std::endl;

    //unsigned char buff[] = "abc";
    unsigned char buff[256] = {};

    ::strcpy((char*)buff,  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

    CheckSumMode mode = CheckSumMode::SHA1;

//using file nonbloking
	std::string fileName = "/dgt/distr/binaries.iso";
    CheckSum _sum1(mode, fileName,  CheckSumType::NoneBloking);
    std::cout << "Start non bloking mode file=" << fileName << std::endl;
    _sum1.start();
    while(_sum1.getActive())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::cout << "End none bloking mode" << std::endl;
    std::cout << "checksum result=" << _sum1.getResult() << std::endl;

//using buffer data
    CheckSum sum1(mode, ::strlen((char*)buff), buff, CheckSumType::Bloking);
    std::cout << "Start bloking mode" << std::endl;
    sum1.start();
    std::cout << "End bloking mode" << std::endl;
    std::cout << "checksum result=" << sum1.getResult() << std::endl;

//using files
    fileName = "/tmp/binaries2.so";
    CheckSum sum2(mode, fileName, CheckSumType::NoneBloking);
    std::cout << "Start nonebloking mode file="<< fileName << std::endl;
    sum2.start();
    while(sum2.getActive())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "End nonebloking mode" << std::endl;
    std::cout << "checksum result=" << sum2.getResult() << std::endl;
    unsigned char* data_hmac = (unsigned char*)"Sample message for keylen=blocklen";
    CheckSum sum3(CheckSumMode::SHA1_HMAC, 34, data_hmac, CheckSumType::Bloking);

//using sha1 hmac
    const char* key = (const char*)"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F";
    unsigned int key_len = 64;

    std::cout << "Start bloking SHA1_HMAC" << std::endl;
    sum3.setHMACParams(key_len, key);
    sum3.start();
    std::cout << "End bloking mode" << std::endl;
    std::cout << "checksum result=" << sum3.getResult() << std::endl;

    return 0;
}
