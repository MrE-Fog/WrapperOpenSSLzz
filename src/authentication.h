#pragma once

#ifndef LIBOCF_AUTHENTICATION_H
#define LIBOCF_AUTHENTICATION_H

#include <memory>
#include <vector>

#include "algorithmbuilder.h"

namespace OCF
{


class Authenticator
{
public:
    Authenticator(bool verbose = false);
    virtual ~Authenticator();
    const tAuth_Result& native_data() const;


    virtual int   GetSpeed() const;
    virtual void  SetSpeed(int value );

    virtual void Init(AuthComponentPtr component, size_t index ,  uint32_t method, uint8_t seed_len, uint8_t* seed_data, uint8_t offset_len, uint8_t* offset_data);
    virtual void Init(AuthComponentPtr component, const CheckSumMode& mode, const std::string& name);
    virtual void InitKey(int keyLength, const char*key, unsigned int tag_len = 20);

    virtual bool IsActive() const;
    virtual bool Complete() const;
    virtual void Start() = 0;
    virtual void Update(float dt) = 0;
    virtual void PrintState() {};

    virtual size_t GetProcessedBlocksAmount() const;

    std::string getResult() const;

    static uint64_t getOffset(const uint8_t offset_len, const uint8_t* offset_data, bool& isError);

protected:    
    tAuth_Result m_native_data;
    PtrAlgorithm algorithm;

    bool m_inited;
    bool m_active;
    bool m_completed;
    bool m_verbose;

    size_t m_index;
    uint32_t m_auth_method;

    uint8_t m_seed_length;
    uint8_t m_seed_data[32];
    uint8_t m_offset_length;
    uint8_t m_offset_data[16];

    uint8_t m_salt_length;
    uint8_t m_salt_data[32];

    uint64_t m_offset;

    uint64_t m_read_cnt;

    int m_speed;
    size_t m_kb_counter;
    char data[1024];

    const size_t max_bytes_to_read = 1024;

    bool inited() const;
    void OnStart();

    virtual void OnComplete();
    virtual bool IsSeedRequired() const;

};


class FakeAuthenticator: public Authenticator
{    
public:    
    FakeAuthenticator();

    virtual void Init(AuthComponentPtr component, size_t index , uint32_t method, uint8_t seed_len, uint8_t* seed_data, uint8_t offset_len, uint8_t* offset_data);
    virtual void Start();
    virtual void Update(float dt);

private:
    float m_timer;
    void FillNativeData();
};


class Authenticator_FileChecksum: public Authenticator
{
public:
    Authenticator_FileChecksum();
    ~Authenticator_FileChecksum();
    void Init(AuthComponentPtr component, size_t index , uint32_t method, uint8_t seed_len, uint8_t* seed_data, uint8_t offset_len, uint8_t* offset_data)  override;
    void Init(AuthComponentPtr component, const CheckSumMode& mode, const std::string &name) override;
    void Start()  override;
    void Update(float dt)  override;
    void PrintState()  override;

    //size_t GetProcessedBlocksAmount() const  override;

    std::string getFileName() const;
    void setFileName(const std::string& getFileName);

protected:
    void ProcessSalt();

    //void OnComplete()  override;
private:
    int fd;

    std::string m_filename;
};

class Authenticator_BufferData: public Authenticator
{
public:
    Authenticator_BufferData(size_t len, unsigned char *ptr);
    ~Authenticator_BufferData();
    void Init(AuthComponentPtr component, const CheckSumMode& mode, const std::string &name) override;
    void Start()  override;
    void Update(float dt)  override;
    void PrintState()  override;

private:
    size_t lenData;
    unsigned char* ptrData;

    char data[1024];
};

}
#endif // LIBOCF_AUTHENTICATION_H
