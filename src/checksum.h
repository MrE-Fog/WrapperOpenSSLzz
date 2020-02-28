#ifndef LIBOCF_CHECKSUM_H
#define LIBOCF_CHECKSUM_H

#include <thread>
#include <atomic>

#include "authentication.h"

namespace OCF
{

enum class CheckSumType
{
    Bloking = 1,
    NoneBloking
};


class CheckSum
{
public:
    CheckSum(CheckSumMode m, const std::string& name, CheckSumType t = CheckSumType::Bloking);

    CheckSum(CheckSumMode m, size_t len, unsigned char*ptr, CheckSumType t = CheckSumType::Bloking);

    ~CheckSum();

    void start();

    bool getActive() const;

    std::string getResult() const;

    void setHMACParams(int keyLength, const char* key, unsigned int tag_len = 20);

protected:

    void run();

private:
    CheckSumMode mode;
    CheckSumType type;

    std::string fileName;
    std::shared_ptr<Authenticator> checksum;

    const int timeout = 50;     // milliseconds

    std::atomic<bool> isActive;
    std::shared_ptr<std::thread> calcThread;
};

}

#endif // LIBOCF_CHECKSUM_H
