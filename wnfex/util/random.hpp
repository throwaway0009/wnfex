#pragma once
#include <Windows.h>

namespace util
{
    inline bool set_priv( const char* priv, BOOL enable )
    {
        HANDLE           token;
        BOOL             res;
        LUID             luid;
        TOKEN_PRIVILEGES tp;

        res = OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token );

        if( res )
        {
            res = LookupPrivilegeValue( NULL, priv, &luid );
            if( res )
            {
                tp.PrivilegeCount = 1;
                tp.Privileges[ 0 ].Luid = luid;
                tp.Privileges[ 0 ].Attributes = ( enable ) ? SE_PRIVILEGE_ENABLED : 0;

                AdjustTokenPrivileges( token, FALSE, &tp, 0, NULL, NULL );
                res = GetLastError() == ERROR_SUCCESS;
            }
            CloseHandle( token );
        }
        return res;
    }
}