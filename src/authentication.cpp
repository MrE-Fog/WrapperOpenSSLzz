#include "authentication.h"

#include <cstring>
#include <iostream>
#include <sstream>

#include <iomanip>
#include <unistd.h>
#include <fcntl.h>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

#define DG2AUTH_CMD_RESULT		2	/*Component authentication result*/
#define FILE_NAME               "/dgt/distr/binaries.iso"

// =================================================================================================
namespace OCF
{

bool Authenticator::inited() const
{
    return m_inited;
}

void Authenticator::OnStart()
{
    m_active = true;
    m_completed = false;
}

void Authenticator::OnComplete()
{
    memset(&m_native_data, 0, sizeof(m_native_data) );
    m_native_data.cmd = DG2AUTH_CMD_RESULT;
    m_native_data.ID = m_index;
    m_native_data.auth_method = m_auth_method;
    m_native_data.status = 0x41;

    if(algorithm)
        algorithm->FillAlgorythmResult(m_native_data);

    //std::cout << "SAS17 | Authenticator::OnComplete" << std::endl;
    m_active = false;
    m_completed = true;
}

bool Authenticator::IsSeedRequired() const
{
    return false;
}

int Authenticator::GetSpeed() const
{
    return m_speed;
}

void Authenticator::SetSpeed(int value)
{
    m_speed = value;
}

Authenticator::Authenticator(bool verbose):
     m_inited{false}
    , m_active{false}
    , m_completed{false}
    , m_verbose{verbose}
    , m_speed{1000}
    , m_kb_counter{0}
{
    if(m_verbose)
    {
        std::cout << "SAS17 | Authenticator::Authenticator()" << std::endl;
    }
}

Authenticator::~Authenticator()
{

}

const tAuth_Result& Authenticator::native_data() const
{
    return m_native_data;
}

uint64_t Authenticator::getOffset(const uint8_t offset_len, const uint8_t *offset_data, bool& isError)
{
    uint64_t res = 0;
    if (offset_len <= 8)
    {
        for (size_t i=0; i< offset_len; ++i)
        {
            res += ((uint64_t)offset_data[i] << (i*8));
        }
    }
    else
    {
        isError = true;
    }

    return res;
}


void Authenticator::Init(AuthComponentPtr /*component*/, size_t index , uint32_t method, uint8_t seed_len, uint8_t* seed_data, uint8_t offset_len, uint8_t* offset_data)
{
    if(m_verbose)
    {
        std::cout << "SAS17 | Authenticator::Init" << std::endl;
    }

    m_inited = true;
    m_active = false;
    m_completed = false;
    m_index = index;
    m_auth_method = method;

    if( IsSeedRequired() )
    {
        if(m_verbose) std::cout << "SAS17 | Authenticator::Init | IsSeedRequired == true" << std::endl;
        m_seed_length = seed_len;
        memcpy(m_seed_data, seed_data, m_seed_length);
    }
    else
    {
        // use seed data as salt
        m_salt_length = seed_len;
        if(m_verbose) std::cout << "SAS17 | Authenticator::Init | IsSeedRequired == false ; salt length " << int (m_salt_length) << std::endl;
        memcpy(m_salt_data, seed_data, m_salt_length);
    }

    m_offset_length = offset_len;
    if(m_verbose) std::cout << "SAS17 | Authenticator::Init |  offset length " << int (m_offset_length) << std::endl;
    memcpy(m_offset_data, offset_data, m_offset_length);

    // read offset
    bool isError = false;
    m_offset = getOffset(offset_len, offset_data, isError);

    if( isError )
    {
        std::cout << "SAS17 Attention: offset error to get";
    }
    else
    {
        if(m_verbose) std::cout << "SAS17 Attention: get offset = " << m_offset << std::endl;
    }

    m_read_cnt = 0;
}

void Authenticator::Init(AuthComponentPtr, const CheckSumMode& mode, const std::string&)
{
    Authenticator::Init(nullptr, 1, 1, 0, nullptr, 0, nullptr);

    algorithm = AlgorithmBuilder::factoryAlgorithm(mode);
}

void Authenticator::InitKey(int keyLength, const char*key, unsigned int tag_len)
{
    if(algorithm)
    {
        algorithm->setHMACParams(keyLength, key, tag_len);
    }
}

bool Authenticator::IsActive() const
{
    return m_active;
}

bool Authenticator::Complete() const
{
    return m_completed;
}

void Authenticator::Start()
{
    OnStart();
}

//void Authenticator::Update(float /*dt*/)
//{

//}

size_t Authenticator::GetProcessedBlocksAmount() const
{
    if( IsActive() || Complete() )
        return m_kb_counter/1024;
    else
        return 0;
}

std::string Authenticator::getResult() const
{
    std::stringbuf buffer;
    std::ostream os(&buffer);

    for(size_t i = 0; i<m_native_data.auth_len; ++i)
    {
        os << std::hex << std::setw(2) << std::setfill('0') << int(m_native_data.auth_data[i]);
    }

    return buffer.str();
}

// =================================================================================================
FakeAuthenticator::FakeAuthenticator()
    :Authenticator()
{
}

void FakeAuthenticator::Init(AuthComponentPtr component, size_t index , uint32_t method, uint8_t seed_len, uint8_t* seed_data, uint8_t offset_len, uint8_t* offset_data)
{
    Authenticator::Init(component, index, method, seed_len, seed_data, offset_len, offset_data);
}

void FakeAuthenticator::Start()
{
    Authenticator::Start();
    m_timer = 2.0f;
}

void FakeAuthenticator::Update(float dt)
{
    if( m_active )
    {
        m_timer -=dt;
        if( m_timer <=0.0f )
        {
            OnComplete();
            FillNativeData();
        }
    }
}

void FakeAuthenticator::FillNativeData()
{
    memset(&m_native_data, 0, sizeof(m_native_data) );
    m_native_data.cmd = DG2AUTH_CMD_RESULT;
    m_native_data.ID = m_index;
    m_native_data.auth_method = m_auth_method;
    m_native_data.status = 0x41;
    m_native_data.auth_len = 16;
    for(size_t i=0; i<m_native_data.auth_len ; ++i )
        m_native_data.auth_data[i] = i;
}

// ==================================================================================
Authenticator_FileChecksum::Authenticator_FileChecksum():
   Authenticator ()
  , fd{-1}
{
}

Authenticator_FileChecksum::~Authenticator_FileChecksum()
{
    if (fd != -1)
    {
        close( fd );
        fd = -1;
    }
}

void Authenticator_FileChecksum::Init(AuthComponentPtr component, size_t index, uint32_t method, uint8_t seed_len, uint8_t* seed_data, uint8_t offset_len, uint8_t* offset_data)
{
    if( component->GetName() == "Distribution" )
    {
        m_filename = FILE_NAME; //Authenticator_FileChecksum::nameFile;
    }
    else
    {
        std::cout << "Error: unsupported component name " << component->GetName() << std::endl;
    }
    m_kb_counter = 0;
    Authenticator::Init(component, index, method, seed_len, seed_data, offset_len, offset_data);

}

void Authenticator_FileChecksum::Init(AuthComponentPtr component, const CheckSumMode& mode, const std::string &name)
{
    m_kb_counter = 0;
    m_filename = name;

    Authenticator::Init(component, mode, name);
}

void Authenticator_FileChecksum::Start()
{
    m_kb_counter = 0;

    std::cout << "Authenticator_FileChecksum filename=" << m_filename << std::endl;

    // Open file
    fd = open( m_filename.c_str(), O_RDONLY | O_LARGEFILE );

    if( fd == -1 )
    {
        std::cout << "Error open file " << m_filename << std::endl;

        perror("Error opening file\n");

        return;
    }

    algorithm->InitAlgorythm();

    ProcessSalt();

    OnStart();
}

void Authenticator_FileChecksum::Update(float /*dt*/)
{
    if (IsActive() )
    {
        if(m_offset > m_read_cnt)
        {
            m_read_cnt = lseek64(fd, m_offset, SEEK_SET);

            if(m_verbose)
                std::cout << "SAS17 | Authenticator_FileChecksum::Update OFFSET=" << m_read_cnt << std::endl;
        }

        for ( size_t i=0 ; i < (size_t)m_speed ; ++i )
        {
            ++m_kb_counter;

            bool need_update = m_read_cnt >= m_offset;

            if( !need_update )
                if(m_verbose) std::cout << "SAS17 | Authenticator_FileChecksum::Update | need_update == false ; m_read_cnt=" << m_read_cnt << " ; m_offset=" << m_offset << std::endl;

            size_t amount_to_read = max_bytes_to_read;

            if(m_offset > m_read_cnt)
            {
                if ( (m_offset-m_read_cnt) < max_bytes_to_read)
                    amount_to_read = (m_offset-m_read_cnt);
            }

            // Read next block
            int len = read( fd, data, amount_to_read );
            m_read_cnt+=len;

            if( need_update )
            {
                // Update sum
                if(algorithm->UpdateAlgorythm(len, data))
                {
                    close(fd);
                    fd = -1;

                    OnComplete();

                    break;
                }
            }
            else
            {
                std::cout << "SAS17 skip update algorythm" << std::endl;
            }
        }
    }
}


void Authenticator_FileChecksum::PrintState()
{
    if(m_verbose)
    {
        std::cout << "PrintState m_kb_counter = " << m_kb_counter << std::endl;
    }
}

//size_t Authenticator_FileChecksum::GetProcessedBlocksAmount() const
//{
//    if( IsActive() || Complete() )
//        return m_kb_counter/1024;
//    else
//        return 0;
//}


void Authenticator_FileChecksum::ProcessSalt()
{
    if( m_salt_length )
    {        
        if(m_verbose) std::cout << "SAS17 | Process salt length " << int(m_salt_length) << std::endl;

        memcpy(data, m_salt_data, m_salt_length);

        algorithm->UpdateAlgorythm(m_salt_length, data);

        close(fd);
        fd = -1;
    }
}

std::string Authenticator_FileChecksum::getFileName() const
{
    return m_filename;
}

void Authenticator_FileChecksum::setFileName(const std::string&filename)
{
    m_filename = filename;
}


Authenticator_BufferData::Authenticator_BufferData(size_t len, unsigned char*ptr):
    Authenticator ()
    , lenData{len}
    , ptrData{ptr}
{
}

Authenticator_BufferData::~Authenticator_BufferData()
{
}

void Authenticator_BufferData::Init(AuthComponentPtr component, const CheckSumMode&mode, const std::string&name)
{
    m_kb_counter = 0;

    Authenticator::Init(component, mode, name);
}

void Authenticator_BufferData::Start()
{
    algorithm->InitAlgorythm();

    OnStart();
}

void Authenticator_BufferData::Update(float /*dt*/)
{
    if (IsActive() )
    {
        unsigned char buff1[max_bytes_to_read];

        for ( size_t i=0; i < (size_t)m_speed; ++i )
        {

            ++m_kb_counter;
            size_t amount_to_read = 0;

            if( (lenData - m_read_cnt) >= max_bytes_to_read)
            {
                amount_to_read = max_bytes_to_read;
            }
            else
            {
                amount_to_read = lenData - m_read_cnt;
            }

            memcpy(buff1 + m_read_cnt, ptrData, amount_to_read);
            m_read_cnt += amount_to_read;

            // Update sum
            if(algorithm->UpdateAlgorythm(amount_to_read, (const char*)buff1))
            {
                OnComplete();
                break;
            }
        }
    }

}

void Authenticator_BufferData::PrintState()
{
    if(m_verbose)
    {
        std::cout << "PrintState m_kb_counter = " << m_kb_counter << std::endl;
    }
}

}
