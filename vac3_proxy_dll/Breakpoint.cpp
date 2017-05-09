#include "Breakpoint.h"
//#include "Patcher.h"

CBreakpoint * Breakpoint;
// you need to initialize it somewhere( Breakpoint = new Breakpoint(); ) because it needs to setup the exception filter

DWORD CBreakpoint::GetMainThreadId( DWORD pID ) // Credits: Azorbix
{
    THREADENTRY32 te32;
    HANDLE hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, pID );// capture all running threads
    te32.dwSize = sizeof( THREADENTRY32 );// sets the size member to the size of the structure
    if( Thread32First( hSnap, &te32 ) )// if the first thread is valid
    {
        do 
        { 
            if( te32.th32OwnerProcessID == pID )// if that's true, the thread owner is the given process, the first thread in the list is the main thread
                return te32.th32ThreadID;// return the main thread
        }while( Thread32Next( hSnap, &te32 ) );// loop until it returns 0
    }
    return 0;
}

LONG WINAPI UnhandledExceptionFilterGateway( struct _EXCEPTION_POINTERS * ExceptionInfo )
{
    return Breakpoint->UnhandledExceptionFilter( ExceptionInfo );//calls the real filter
}

CBreakpoint::CBreakpoint()
{
    AddVectoredExceptionHandler( 1, UnhandledExceptionFilterGateway );// Adds a VEH( it gets called before the SEHs are getting called ), 1 = it gets called at first - even if there are other VEHs
}

void ThreadGateway()
{
    Breakpoint->SetupThread(0);//calls the class func
}

void CBreakpoint::ApplyBreakpoint()
{
    // We need to create a second thread because if we would freeze our own thread the whole application will freeze
    CreateThread( 0, 0, (LPTHREAD_START_ROUTINE)ThreadGateway, 0, 0, 0 );
}

void CBreakpoint::SetupThread(DWORD tid)
{
    DWORD dwThreadId = GetMainThreadId( GetCurrentProcessId() );// look at the commentst inside GetMainThreadId

    if(tid)
        dwThreadId = tid;

    HANDLE hThread = OpenThread( THREAD_ALL_ACCESS, false, dwThreadId );// opens the main thread with all access privileges


    if( hThread )// if the handle is valid
    {
        CONTEXT ctx = { CONTEXT_ALL };

        // NOTE: remove the 'o' to call the original GetThreadContext if you haven't hooked it
        GetThreadContext( hThread, &ctx );//get its current context

        if( (int)vBreakpoint.size() >= 1 )//if there are 1 or more breakpoints on the stack
        {
            ctx.Dr0 = vBreakpoint[0].dwAddress;// set Dr0( later 1,2 and 3) to its address
            ctx.Dr7 = 0x00000001;//enable the flag that indicates wether it should break if the specific Debug register is reached
        }
        else
            ctx.Dr0 = 0;// if there aren't 1 or more breakpoints, set it to 0 ( to prevent errors )
        if( (int)vBreakpoint.size() >= 2 )
        {
            ctx.Dr1 = vBreakpoint[1].dwAddress;
            ctx.Dr7 |= 0x00000004;
        }
        else
            ctx.Dr1 = 0;
        if( (int)vBreakpoint.size() >= 3 )
        {
            ctx.Dr2 = vBreakpoint[2].dwAddress;
            ctx.Dr7 |= 0x00000010;
        }
        else
            ctx.Dr2 = 0;
        if( (int)vBreakpoint.size() >= 4 )
        {
            ctx.Dr3 = vBreakpoint[3].dwAddress;
            ctx.Dr7 |= 0x00000040;
        }
        else
            ctx.Dr3 = 0;

        SetThreadContext( hThread, &ctx );// set the modified context
        CloseHandle( hThread );// close the handle to the thread
    }

}

void CBreakpoint::Clear()
{
    vBreakpoint.clear();// clear breakpoint stack
    ApplyBreakpoint();// sets all Debug registers to 0
}

void CBreakpoint::AddBreakpoint( DWORD dwAddress, DWORD dwEip, PVECTORED_EXCEPTION_HANDLER pCustomFilter )
{
    if( vBreakpoint.size() >= 4 )
        return;// we can't set more than 4 breakpoints
    vBreakpoint.push_back( sBreakpoint( dwAddress, dwEip, (DWORD)pCustomFilter ) );// add the breakpoint to the stack
    //ApplyBreakpoint();// apply the breakpoint
}

void CBreakpoint::RemoveBreakpoint( DWORD dwAddress )
{
    for( int i = 0; i < (int)vBreakpoint.size(); i++ )// loop through the breakpoint stack
        if( vBreakpoint[i].dwAddress == dwAddress ) // if it's the one we need
            vBreakpoint.erase( vBreakpoint.begin() + i );// erase it from the stack
    ApplyBreakpoint();// apply the breakpoints without the breakpoint at the given address
}

LONG WINAPI CBreakpoint::UnhandledExceptionFilter( struct _EXCEPTION_POINTERS *ExceptionInfo )
{
    if( ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP )// our breakpoints are always single_step exceptions
    {
        for( int i = 0; i < (int)vBreakpoint.size(); i++ )//loop through the stack
            if( vBreakpoint[i].dwAddress == (DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress )// if it's the breakpoint that was reached
            {
                if( vBreakpoint[i].dwCustomFilter )//is there a custon filter function ?
                    return ( (PVECTORED_EXCEPTION_HANDLER)vBreakpoint[i].dwCustomFilter )( ExceptionInfo );// call it
                ExceptionInfo->ContextRecord->Eip = vBreakpoint[i].dwEip;//else forward it to the given EIP
                return EXCEPTION_CONTINUE_EXECUTION;// continue execution(obviously)
            }

            if( ExceptionInfo->ContextRecord->Eip == ExceptionInfo->ContextRecord->Dr0 )// if Dr0 is still set(for some reason)
            {
                ExceptionInfo->ContextRecord->Dr0 = 0;//reset it
                return EXCEPTION_CONTINUE_EXECUTION;// continue execution
            }
            else if( ExceptionInfo->ContextRecord->Eip == ExceptionInfo->ContextRecord->Dr1 )
            {
                ExceptionInfo->ContextRecord->Dr1 = 0;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else if( ExceptionInfo->ContextRecord->Eip == ExceptionInfo->ContextRecord->Dr2 )
            {
                ExceptionInfo->ContextRecord->Dr2 = 0;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else if( ExceptionInfo->ContextRecord->Eip == ExceptionInfo->ContextRecord->Dr3 )
            {
                ExceptionInfo->ContextRecord->Dr3 = 0;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
    }
    return EXCEPTION_CONTINUE_SEARCH;// forward the other exceptions to the application
}

