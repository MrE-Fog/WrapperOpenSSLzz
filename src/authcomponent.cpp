#include "authcomponent.h"
#include <cstring>

//const std::string Authenticator_FileChecksum::nameFile{"/dgt/distr/binaries.iso"};

namespace OCF
{

void AuthComponent::ResetNativeData()
{
    memset(&m_native_data,0, sizeof(sAuthComponent) );
}

AuthComponent::AuthComponent(const std::string &name, uint32_t _auth_mask):
    m_name(name)
  , max_name_length(AUTH_MAX_NAMELEN)
{
    ResetNativeData();
    int name_length = m_name.length();
    if( name_length > max_name_length )
        name_length = max_name_length;
    std::copy(m_name.begin(), m_name.begin()+name_length, m_native_data.Name);
    m_native_data.size_len = name_length;

    m_native_data.auth_methods_mask = _auth_mask;
    m_native_data.size_len = 0;
}

const sAuthComponent &AuthComponent::native_data() const
{
    return m_native_data;
}

const std::string &AuthComponent::GetName() const
{
    return m_name;
}

}
