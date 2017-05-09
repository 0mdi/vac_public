int main ( int argc, char *argv[ ], char *envp[ ] )
{
	BOOL iReturn;

	char szDirectory[256];

	DWORD dwBytesRead, dwBytesWritten, dwFileSize, dwReturnValue;

	DWORD dwOldProtect, dwVACBase, dwVACScan, dwVACSize;
	
	FARPROC ( __cdecl* Startup3 )( HANDLE, HANDLE, HANDLE, HANDLE );

	FARPROC ( __cdecl* StartupData )( HANDLE );

	FARPROC Enter3;

	HANDLE hFindFileHandle, hHeap, hReadPipeChild, hReadPipeParent, hTargetHandle, hWritePipeChild, hWritePipeParent,
		hVACFile, hVACThread;

	HMODULE hVAC;

	int i, iErrorCode;

	LPVOID lpHeap;

	SECURITY_ATTRIBUTES PipeAttributes;

	PIMAGE_DOS_HEADER lpImageDosHeader;
	PIMAGE_NT_HEADERS lpImageNtHeaders;
	PIMAGE_SECTION_HEADER lpSectionHeader;

	SIZE_T sHeapSize;

	TCHAR szTempFileName[MAX_PATH];  
	TCHAR lpTempPathBuffer[MAX_PATH];

	UINT uiReturnValue;

	WIN32_FIND_DATA finddata;
	
	hHeap = HeapCreate ( HEAP_NO_SERIALIZE, 0x40000, 0x40000 );

	iErrorCode = GetLastError();

	// TODO: Translate error codes into messages using FormatMessage, see MSDN

	if ( hHeap == NULL )
	{
		printf ( "HeapCreate failed with errorcode %i.\n", iErrorCode );

		return 0;
	}
	else
	{
		lpHeap = HeapAlloc ( hHeap, HEAP_NO_SERIALIZE, 0x30000 );

		iErrorCode = GetLastError();

		if ( lpHeap == NULL )
		{
			printf ( "HeapAlloc failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		memset ( ( LPVOID )lpHeap, 0, 0x30000 );
	}
	if ( GetCurrentDirectoryA ( 256, szDirectory ) != 0 )
	{
		strcpy_s ( g_szDirectory, 256, szDirectory );

		strcat_s ( szDirectory, 256, "\\" );

		strcat_s ( szDirectory, 256, "SourceInit.dat" );

		hFindFileHandle = FindFirstFileA ( "SourceInit.dat", &finddata );

		iErrorCode = GetLastError();

		if ( hFindFileHandle == NULL )
		{
			printf ( "FindFirstFileA failed with errorcode %i.\n", iErrorCode );

			return 0;
		}
		
		hVACFile = CreateFileA ( szDirectory, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

		iErrorCode = GetLastError();

		if ( hVACFile == INVALID_HANDLE_VALUE )
		{
			printf ( "CreateFileA failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		dwFileSize = GetFileSize ( hVACFile, NULL );

		iErrorCode = GetLastError();

		if ( dwFileSize == -1 )
		{			
			printf ( "Error code %i.\n", iErrorCode );

			return 0;
		}

		g_dwFileSize = dwFileSize;

		sHeapSize = HeapSize ( hHeap, HEAP_NO_SERIALIZE, lpHeap );

		iErrorCode = GetLastError();

		if ( sHeapSize == 0 || sHeapSize == -1 )
		{
			printf ( "HeapSize failed with errorcode %i.\n", GetLastError() );

			return 0;
		}
		if ( dwFileSize > sHeapSize )
		{
			printf ( "VAC file is larger than heap.\n" );

			printf ( "Attempting to reallocate heap to read the file to continue normally.\n" );

			printf ( "If this fails then the application will attempt again with VirtualAlloc.\n" );

			lpHeap = HeapReAlloc ( hHeap, HEAP_NO_SERIALIZE, lpHeap, dwFileSize );

			iErrorCode = GetLastError();

			if ( lpHeap == NULL )
			{
				printf ( "HeapReAlloc failed with errorcode %i.\n", iErrorCode );

				printf ( "Attempting to allocate memory with VirtualAlloc.\n" );

				// Implement this if you fail hard
			}
		}

		iReturn = ReadFile ( hVACFile, lpHeap, dwFileSize, &dwBytesRead, NULL );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "ReadFile failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		iReturn = CloseHandle ( hVACFile );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "CloseHandle failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		dwReturnValue = GetTempPathA ( 0x104, lpTempPathBuffer );
	
		iErrorCode = GetLastError();

		if ( dwReturnValue > 0x104 || dwReturnValue == 0 )
		{
			printf ( "GetTempPathA failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		uiReturnValue = GetTempFileNameA ( lpTempPathBuffer, "~", 0, szTempFileName );

		iErrorCode = GetLastError();

		if ( uiReturnValue == 0 )
		{
			printf ( "GetTempFileNameA failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		hVACFile = CreateFileA ( szTempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );

		iErrorCode = GetLastError();

		if ( hVACFile == INVALID_HANDLE_VALUE )
		{
			printf ( "CreateFileA failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		iReturn = WriteFile ( hVACFile, lpHeap, dwFileSize, &dwBytesWritten, NULL );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "WriteFile failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		iReturn = CloseHandle ( hVACFile );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "CloseHandle failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		hVAC = LoadLibraryA ( szTempFileName );

		iErrorCode = GetLastError();

		if ( hVAC == NULL )
		{
			printf ( "LoadLibraryA failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		PipeAttributes.lpSecurityDescriptor = NULL;
		PipeAttributes.nLength = sizeof ( SECURITY_ATTRIBUTES );
		PipeAttributes.bInheritHandle = TRUE;

		iReturn = CreatePipe ( &hReadPipeChild, &hWritePipeChild, &PipeAttributes, 0 );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "CreatePipe failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		iReturn = DuplicateHandle ( GetCurrentProcess(), hReadPipeChild, GetCurrentProcess(), &hTargetHandle, 0, 1, 2 );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "DuplicateHandle failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		iErrorCode = CloseHandle ( hReadPipeChild );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "CloseHandle failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		hReadPipeChild = hTargetHandle;

		hReadPipeChild = CreateEventA ( &PipeAttributes, 0, 0, 0 );

		iErrorCode = GetLastError();

		if ( hReadPipeChild == NULL )
		{
			printf ( "CreateEventA failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		iReturn = CreatePipe ( &hReadPipeParent, &hWritePipeParent, &PipeAttributes, 0 );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "CreatePipe failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		iReturn = DuplicateHandle ( GetCurrentProcess(), hWritePipeParent, GetCurrentProcess(), &hTargetHandle, 0, 1, 2 );
			
		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "DuplicateHandle failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		iErrorCode = CloseHandle ( hWritePipeParent );

		iErrorCode = GetLastError();

		if ( iReturn != 1 )
		{
			printf ( "CloseHandle failed with errorcode %i.\n", iErrorCode );
			
			return 0;
		}

		hWritePipeParent = hTargetHandle;

		hWritePipeParent = CreateEventA ( &PipeAttributes, 0, 0, 0 );

		iErrorCode = GetLastError();

		if ( hWritePipeParent == NULL )
		{
			printf ( "CreateEventA failed with errorcode %i.\n", iErrorCode );

			return 0;
		}

		Startup3 = ( FARPROC ( __cdecl* )( HANDLE, HANDLE, HANDLE, HANDLE ) )GetProcAddress ( hVAC, "Startup3" );

		if ( Startup3 == NULL )
			return 0;

		Enter3 = GetProcAddress ( hVAC, "Enter3" );

		if ( Enter3 == NULL )
			return 0;

		StartupData = ( FARPROC ( __cdecl* )( HANDLE ) )GetProcAddress ( hVAC, "StartupData" );

		if ( StartupData == NULL )
			return 0;

		if ( Startup3 ( hReadPipeParent, hWritePipeChild, hWritePipeParent, hReadPipeChild ) )
		{
			hVACThread = CreateThread ( NULL, 0, ( LPTHREAD_START_ROUTINE )Enter3, NULL, 0, NULL ); // they create a thread for tier0 minidump with enter3 as parameter, but let's just be lazy here
																									// and say GIAP DE PHUC DAT
			iErrorCode = GetLastError();

			if ( iReturn != 1 )
			{
				printf ( "CreateThread failed with errorcode %i.\n", iErrorCode );

				system ( "pause" );

				return 0;
			}

			StartupData ( hVACThread ); // pass in thread handle
					
			lpImageDosHeader = ( PIMAGE_DOS_HEADER )( ( DWORD )hVAC );

			dwVACBase = ( DWORD )hVAC;

			if ( lpImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE )
			{
				lpImageNtHeaders = ( PIMAGE_NT_HEADERS )( ( DWORD )hVAC + lpImageDosHeader->e_lfanew );

				dwVACSize = lpImageNtHeaders->OptionalHeader.SizeOfImage;

				if ( lpImageNtHeaders->Signature == IMAGE_NT_SIGNATURE )
				{
					lpSectionHeader = IMAGE_FIRST_SECTION ( lpImageNtHeaders );
			                 
					for ( i = 0; i < lpImageNtHeaders->FileHeader.NumberOfSections; i++ )
					{
						if ( !strcmp ( ( PCHAR )lpSectionHeader->Name, ".text" ) )
						{
							g_dwVACCodeBase = lpSectionHeader->VirtualAddress;
							g_dwVACCodeSize = lpSectionHeader->SizeOfRawData;
						}
						
						if ( g_dwVACCodeBase && g_dwVACCodeSize )
							break;

						lpSectionHeader++;
					}
				}
			}

			iReturn = HeapFree ( hHeap, HEAP_NO_SERIALIZE, lpHeap );

			iErrorCode = GetLastError();

			if ( iReturn != 1 )
			{
				printf ( "HeapFree failed with errorcode %i.\n", iErrorCode );

				return 0;
			}
		}
	}
	else
	{
		printf ( "GetCurrentDirectoryA failed with errorcode %i.\n", iErrorCode );

		return 0;
	}

	iReturn = VirtualProtect ( ( LPVOID )( dwVACBase + 0x106FE ), 0x5, PAGE_EXECUTE_READWRITE, &dwOldProtect );
	
	iErrorCode = GetLastError();

	if ( iReturn != 1 )
	{
		printf ( "VirtualProtect failed with errorcode %i\n", iErrorCode );

		return 0;
	}

	*( PBYTE )( dwVACBase + 0x106FE ) = 0xC3; // patch the code to encrypt the scan results
	*( PBYTE )( dwVACBase + 0x106FF ) = 0x0;
	*( PBYTE )( dwVACBase + 0x10700 ) = 0x0;
	*( PBYTE )( dwVACBase + 0x10701 ) = 0x0;
	*( PBYTE )( dwVACBase + 0x10702 ) = 0x0;

	// if you don't care to patch and bother to decrypt it, the packet encrypt ice key is right after the function decrypt ice key
	// but you will need to shift the bits around a bit, and I haven't bothered with reversing it
	// so this is clearly the easier solution

	iReturn = VirtualProtect ( ( LPVOID )( dwVACBase + 0x106FE ), 0x5, dwOldProtect, &dwOldProtect );
	
	iErrorCode = GetLastError();

	if ( iReturn != 1 )
	{
		printf ( "VirtualProtect failed with errorcode %i\n", iErrorCode );

		return 0;
	}

	int iResponseSize, iRemainingPacketSize;

	iRemainingPacketSize = 0xA0;

	for ( i = 0; i < 28; i++ )
	{	
		memcpy ( g_szCopiedVACPacket, g_szVACPacket[i], 180 );

		switch ( g_szVACPacket[i][8] )
		{
			case 0xB:
			{
				dwVACScan = 0x100072A9;

				__asm
				{
					LEA EAX, iResponseSize
					PUSH EAX
					LEA EAX, g_szResponsePacket
					PUSH EAX
					LEA EAX, iRemainingPacketSize
					PUSH EAX
					LEA EAX, g_szCopiedVACPacket[0x10]
					PUSH EAX
					CALL dwVACScan
					ADD ESP, 0x10
				}

			}
			break;

			case 0xC:
			{
				dwVACScan = 0x100044DC;

				__asm
				{
					LEA EAX, iResponseSize
					PUSH EAX
					LEA EAX, g_szResponsePacket
					PUSH EAX
					LEA EAX, iRemainingPacketSize
					PUSH EAX
					LEA EAX, g_szCopiedVACPacket[0x10]
					PUSH EAX
					CALL dwVACScan
					ADD ESP, 0x10
				}

			}
			break;

			case 0xD:
			{
				dwVACScan = 0x10003535;

				__asm
				{
					LEA EAX, iResponseSize
					PUSH EAX
					LEA EAX, g_szResponsePacket
					PUSH EAX
					PUSH 4
					LEA EAX, iRemainingPacketSize
					PUSH EAX
					LEA EAX, g_szCopiedVACPacket[0x10]
					PUSH EAX
					CALL dwVACScan
					ADD ESP, 0x10
				}

			}
			break;

			case 0xE:
			{
				dwVACScan = 0x1000295F;

				__asm
				{
					LEA EAX, iResponseSize
					PUSH EAX
					LEA EAX, g_szResponsePacket
					PUSH EAX
					LEA EAX, iRemainingPacketSize
					PUSH EAX
					LEA EAX, g_szCopiedVACPacket[0x10]
					PUSH EAX
					CALL dwVACScan
					ADD ESP, 0x10
				}

			}
			break;

			case 0xF:
			{
				dwVACScan = 0x100057F5;

				__asm
				{
					LEA EAX, iResponseSize
					PUSH EAX
					LEA EAX, g_szResponsePacket
					PUSH EAX
					LEA EAX, iRemainingPacketSize
					PUSH EAX
					LEA EAX, g_szCopiedVACPacket[0x10]
					PUSH EAX
					CALL dwVACScan
					ADD ESP, 0x10
				}

			}
			break;
		}

		if ( iResponseSize <= 4  )
			printf ( "Fucking fail faggot goddamn you son of a bitch go choke and die on horse cum you dumbass shitface.\n" );
		else
			LogScan();
	}

	iReturn = CloseHandle ( hVAC );

	iErrorCode = GetLastError();

	if ( iReturn != 1 )
	{
		printf ( "CloseHandle failed with errorcode %i.\n", iErrorCode );

		return 0;
	}

	return 0;
}