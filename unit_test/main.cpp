#include <iostream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "checksum.h"

using namespace std;
using namespace OCF;

using ::testing::AtLeast;
using ::testing::Return;
using ::testing::InSequence;
using ::testing::_;

TEST(CheckSumMode, SHA1)
{
    unsigned char buff[256] = {};
    ::strcpy((char*)buff,  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

    std::string etalon = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";

	CheckSum sum1(CheckSumMode::SHA1, ::strlen((char*)buff), buff, CheckSumType::Bloking);
	sum1.start();
	//std::cout << sum1.getResult() << std::endl;

	ASSERT_EQ(sum1.getResult() == etalon, true);
}

TEST(CheckSumMode, MD5)
{
    unsigned char buff[256] = {};
    ::strcpy((char*)buff,  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

    std::string etalon = "8215ef0796a20bcaaae116d3876c664a";

	CheckSum sum1(CheckSumMode::MD5, ::strlen((char*)buff), buff, CheckSumType::Bloking);
	sum1.start();

	ASSERT_EQ(sum1.getResult() == etalon, true);
}

TEST(CheckSumMode, SHA1_HMAC_1)
{
    int key_length = 64;
    unsigned char key[] = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F";

    unsigned char buff[256] = {};
    ::strcpy((char*)buff,  "Sample message for keylen=blocklen");

    std::string etalon = "5fd596ee78d5553c8ff4e72d266dfd192366da29";

	CheckSum sum1(CheckSumMode::SHA1_HMAC, ::strlen((char*)buff), buff, CheckSumType::Bloking);
	sum1.setHMACParams(key_length, (const char*)key);
	sum1.start();

	//std::cout << sum1.getResult() << std::endl;

	ASSERT_EQ(sum1.getResult() == etalon, true);
}

bool caseInsensitiveStringCompare( const std::string& str1, const std::string& str2 )
{
    std::string str1Cpy( str1 );
    std::string str2Cpy( str2 );
    std::transform( str1Cpy.begin(), str1Cpy.end(), str1Cpy.begin(), ::tolower );
    std::transform( str2Cpy.begin(), str2Cpy.end(), str2Cpy.begin(), ::tolower );
    return ( str1Cpy == str2Cpy );
}

TEST(CheckSumMode, SHA1_HMAC_2)
{
    int key_length = 20;
    unsigned char key[] = "000102030405060708090A0B0C0D0E0F10111213";

    unsigned char buff[256] = {};
    ::strcpy((char*)buff,  "Sample message for keylen<blocklen");

    std::string etalon = "4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807";

	CheckSum sum1(CheckSumMode::SHA1_HMAC, ::strlen((char*)buff), buff, CheckSumType::Bloking);
	sum1.setHMACParams(key_length, (const char*)key);
	sum1.start();

	//std::cout << sum1.getResult() << std::endl;
	ASSERT_EQ(caseInsensitiveStringCompare(sum1.getResult(), etalon), true);
}

TEST(CheckSumMode, SHA1_HMAC_3)
{
    int key_length = 100;
    unsigned char key[] = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263";

    unsigned char buff[256] = {};
    ::strcpy((char*)buff,  "Sample message for keylen=blocklen");

    std::string etalon = "2D51B2F7750E410584662E38F133435F4C4FD42A";

	CheckSum sum1(CheckSumMode::SHA1_HMAC, ::strlen((char*)buff), buff, CheckSumType::Bloking);
	sum1.setHMACParams(key_length, (const char*)key);
	sum1.start();

	//std::cout << sum1.getResult() << std::endl;
	ASSERT_EQ(caseInsensitiveStringCompare(sum1.getResult(), etalon), true);
}

TEST(CheckSumMode, SHA1_HMAC_4)
{
    int key_length = 49;
    int tag = 12;

    unsigned char key[] = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30";

    unsigned char buff[256] = {};
    ::strcpy((char*)buff,  "Sample message for keylen<blocklen, with truncated tag");

    std::string etalon = "FE3529565CD8E28C5FA79EAC";

	CheckSum sum1(CheckSumMode::SHA1_HMAC, ::strlen((char*)buff), buff, CheckSumType::Bloking);
	sum1.setHMACParams(key_length, (const char*)key, tag);
	sum1.start();

	//std::cout << sum1.getResult() << std::endl;
	ASSERT_EQ(caseInsensitiveStringCompare(sum1.getResult(), etalon), true);
}



int main(int argc, char *argv[])
{
    cout << "Unit test libOCF" << endl;    
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

