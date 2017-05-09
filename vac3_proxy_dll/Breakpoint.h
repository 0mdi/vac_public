#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

//typedef BOOL ( WINAPI * tGetThreadContext )( HANDLE hThread, LPCONTEXT lpContext);
//tGetThreadContext oGetThreadContext;// not needed if you haven't hooked GetThreadContext

class CBreakpoint
{
    struct sBreakpoint
    {
        DWORD dwAddress, dwEip, dwCustomFilter;
        sBreakpoint( DWORD dw_Address, DWORD dw_Eip, DWORD dw_CustomFilter = 0 )
        {
            dwAddress = dw_Address;
            dwEip = dw_Eip;
            dwCustomFilter = dw_CustomFilter;
        }
    };
    std::vector<sBreakpoint> vBreakpoint;

public:

    CBreakpoint();

    DWORD GetMainThreadId( DWORD pID );

    void ApplyBreakpoint();
    void SetupThread(DWORD tid);

    void Clear();
    void AddBreakpoint( DWORD dwAddress, DWORD dwEip, PVECTORED_EXCEPTION_HANDLER pCustomFilter = 0 );
    void RemoveBreakpoint( DWORD dwAddress );

    LONG WINAPI UnhandledExceptionFilter( struct _EXCEPTION_POINTERS *ExceptionInfo );
};

extern CBreakpoint * Breakpoint;