#ifndef AUTHCOMPONENT_H
#define AUTHCOMPONENT_H

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <memory>

namespace OCF
{

typedef struct
{
    uint8_t     cmd;
    uint8_t     ID;
    uint32_t	auth_method;
    uint8_t     status;
    uint8_t     auth_len;
    uint8_t     auth_data[128];
} __attribute__ ((packed)) tAuth_Result;

struct AuthStatus
{
    enum Id
    {
        Success                             = 0x41 // – authentication complete (successful)
        ,ComponentNotExist                  = 0x80 // – component doesn’t exist
        , ComponentDisabled                 = 0x81 // – component disabled or otherwise unavailable
        , InvalidCommand                    = 0x82 // – invalid command
        , AuthenticationFailed              = 0xC0 // – authentication failed (reason unknown/unspecified)
        , AuthenticationAborted             = 0xC1 // - authentication aborted (component list changed)
        , ComponentNotSupportAuthentication = 0xC2 // – component doesn’t support authentication
        , RequestedMethodNotSupported       = 0xC3 // – requested authentication method not supported
        , InvalidData                       = 0xC4 // – invalid data for requested authentication method
        , CannotAuthenticateNow             = 0xC5 // – component cannot be authenticated at this time
    };
};

#define AUTH_MAX_NAMELEN	127
#define AUTH_MAX_COMPONENTS	10

typedef struct
{
    char Name[AUTH_MAX_NAMELEN];
    uint8_t size_len;
    uint8_t size[16];
    uint32_t auth_methods_mask;
} __attribute__ ((packed))
sAuthComponent;


class AuthComponent
{
private:
    sAuthComponent m_native_data;
    std::string m_name;
    const int max_name_length;

    void ResetNativeData();
public:
    AuthComponent( const std::string& name, uint32_t auth_mask  );
    const sAuthComponent& native_data() const;
    const std::string& GetName() const;

};

using AuthComponentPtr = std::shared_ptr<AuthComponent>;

}

#endif // AUTHCOMPONENT_H
