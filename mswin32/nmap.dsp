# Microsoft Developer Studio Project File - Name="nmap" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=nmap - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "nmap.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "nmap.mak" CFG="nmap - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "nmap - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "nmap - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "nmap - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "nmap___Win32_Release"
# PROP BASE Intermediate_Dir "nmap___Win32_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /GX /O1 /I "." /I ".." /I "../nbase" /I "mswin32\winip" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D HAVE_CONFIG_H=1 /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib iphlpapi.lib delayimp.lib libpcap.lib /nologo /subsystem:console /machine:I386 /libpath:"winip" /libpath:"lib" /delayload:packet.dll /delay:nobind /opt:nowin98 /delayload:iphlpapi.dll
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "nmap - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "nmap___Win32_Debug"
# PROP BASE Intermediate_Dir "nmap___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W2 /Gm /GX /ZI /Od /I "." /I ".." /I "../nbase" /I "mswin32\winip" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D HAVE_CONFIG_H=1 /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib iphlpapi.lib delayimp.lib libpcap.lib /nologo /subsystem:console /profile /debug /machine:I386 /libpath:"winip" /libpath:"lib" /delayload:packet.dll /delay:nobind

!ENDIF 

# Begin Target

# Name "nmap - Win32 Release"
# Name "nmap - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "Windows"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\globals.c
# End Source File
# Begin Source File

SOURCE=.\nmap.rc
# End Source File
# Begin Source File

SOURCE=.\winip\pcapsend.c
# End Source File
# Begin Source File

SOURCE=.\winip\rawrecv.c
# End Source File
# Begin Source File

SOURCE=.\winfix.c
# End Source File
# Begin Source File

SOURCE=.\winip\winip.c
# End Source File
# Begin Source File

SOURCE=.\wintcpip.c
# End Source File
# End Group
# Begin Source File

SOURCE=..\charpool.c
# End Source File
# Begin Source File

SOURCE=..\error.c
# End Source File
# Begin Source File

SOURCE=..\nbase\getopt.c
# End Source File
# Begin Source File

SOURCE=..\nbase\getopt1.c
# End Source File
# Begin Source File

SOURCE=..\nbase\inet_aton.c
# End Source File
# Begin Source File

SOURCE=..\nbase\nbase_misc.c
# End Source File
# Begin Source File

SOURCE=..\nbase\nbase_str.c
# End Source File
# Begin Source File

SOURCE=..\nmap.c
# End Source File
# Begin Source File

SOURCE=..\osscan.c
# End Source File
# Begin Source File

SOURCE=..\output.c
# End Source File
# Begin Source File

SOURCE=..\portlist.c
# End Source File
# Begin Source File

SOURCE=..\protocols.c
# End Source File
# Begin Source File

SOURCE=..\rpc.c
# End Source File
# Begin Source File

SOURCE=..\scan_engine.c
# End Source File
# Begin Source File

SOURCE=..\services.c
# End Source File
# Begin Source File

SOURCE=..\targets.c
# End Source File
# Begin Source File

SOURCE=..\tcpip.c
# End Source File
# Begin Source File

SOURCE=..\timing.c
# End Source File
# Begin Source File

SOURCE=..\utils.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Group "Win Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\NET\Bpf.h
# End Source File
# Begin Source File

SOURCE=.\winip\iphlpapi.h
# End Source File
# Begin Source File

SOURCE=.\PACKET32.H
# End Source File
# Begin Source File

SOURCE=.\Pcap.h
# End Source File
# Begin Source File

SOURCE=.\winclude.h
# End Source File
# Begin Source File

SOURCE=.\winfix.h
# End Source File
# Begin Source File

SOURCE=.\winip\winip.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\charpool.h
# End Source File
# Begin Source File

SOURCE=.\config.h
# End Source File
# Begin Source File

SOURCE=..\error.h
# End Source File
# Begin Source File

SOURCE=..\nbase\getopt.h
# End Source File
# Begin Source File

SOURCE=..\global_structures.h
# End Source File
# Begin Source File

SOURCE=.\NETINET\IP.H
# End Source File
# Begin Source File

SOURCE=..\nbase\nbase.h
# End Source File
# Begin Source File

SOURCE=..\nbase\nbase_config.h
# End Source File
# Begin Source File

SOURCE=..\nmap.h
# End Source File
# Begin Source File

SOURCE=..\osscan.h
# End Source File
# Begin Source File

SOURCE=..\output.h
# End Source File
# Begin Source File

SOURCE=..\portlist.h
# End Source File
# Begin Source File

SOURCE=..\protocols.h
# End Source File
# Begin Source File

SOURCE=..\rpc.h
# End Source File
# Begin Source File

SOURCE=..\scan_engine.h
# End Source File
# Begin Source File

SOURCE=..\services.h
# End Source File
# Begin Source File

SOURCE=.\strings.h
# End Source File
# Begin Source File

SOURCE=..\targets.h
# End Source File
# Begin Source File

SOURCE=.\NETINET\TCP.H
# End Source File
# Begin Source File

SOURCE=..\tcpip.h
# End Source File
# Begin Source File

SOURCE=..\timing.h
# End Source File
# Begin Source File

SOURCE=..\utils.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\icon1.ico
# End Source File
# End Group
# End Target
# End Project
