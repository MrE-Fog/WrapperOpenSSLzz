#include <iostream>
#include "checksum.h"

namespace OCF
{

CheckSum::CheckSum(CheckSumMode m, const std::string&name, CheckSumType t):
    mode{m},
    type{t},
    fileName{name},    
    calcThread{nullptr}
{


    checksum = std::make_shared<Authenticator_FileChecksum>();

    std::cout << "Constructor CheckSum FileChecksum file=" << name << std::endl;

    if(checksum)
    {
        checksum->Init(std::make_shared<AuthComponent>("Distribution", 1), m, name);

        isActive =  true;
    }
    else
    {
        isActive = false;
    }
}

CheckSum::CheckSum(CheckSumMode m, size_t len, unsigned char*ptr, CheckSumType t):
    mode{m},
    type{t},
    calcThread{nullptr}
{
    checksum = std::make_shared<Authenticator_BufferData>(len, ptr);

    std::cout << "Constructor CheckSum BufferData len=" << len << std::endl;

    if(checksum)
    {
        checksum->Init(std::make_shared<AuthComponent>("Distribution", 1), m, "");
        isActive = true;
    }
    else
    {
        isActive = false;
    }
}

CheckSum::~CheckSum()
{
    if(calcThread)
    {
        isActive = false;
        calcThread->join();
    }

    //std::cout << "~CheckSum() " << std::endl;
}


void CheckSum::start()
{
    if(type == CheckSumType::NoneBloking)
    {
        calcThread = std::make_shared<std::thread>(&CheckSum::run, this);
    }
    else
    {
        run();
    }
}

void CheckSum::run()
{
    float ft = 1.0;

    if(checksum == nullptr)
    {
        return;
    }

    isActive = true;
    checksum->Start();


    while(isActive)
    {
        if(checksum->IsActive())
        {
            checksum->PrintState();
        }
        else
        {
            //std::cout << "end calc checksum" << std::endl;
            isActive = false;
            break;
        }
        checksum->Update(ft);
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
    }

}

bool CheckSum::getActive() const
{
    return isActive;
}

std::string CheckSum::getResult() const
{
    if(checksum == nullptr)
    {
        return std::string("");
    }
    else
    {
        return checksum->getResult();
    }
}

void CheckSum::setHMACParams(int keyLength, const char*key, unsigned int tag_len)
{
    checksum->InitKey(keyLength, key, tag_len);
}

}
