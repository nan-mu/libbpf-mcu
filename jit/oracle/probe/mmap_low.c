#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
int main(void) {
  unsigned long bases[] = {0x10000, 0x10000000, 0x80000000, 0xf0000000,
                           0x100000000, 0x200000000};
  for (unsigned i = 0; i < sizeof(bases)/sizeof(bases[0]); i++) {
    void *p = mmap((void*)bases[i], 0x40000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANON|MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) { printf("base %#lx FAILED errno=%d\n", bases[i], errno); continue; }
    memset(p, 0x5a, 0x40000);
    printf("base %#lx -> %p %s\n", bases[i], p, ((unsigned long)p == bases[i]) ? "EXACT" : "MOVED");
    munmap(p, 0x40000);
  }
  void *q = mmap(NULL, 0x40000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
  printf("hintless -> %p\n", q);
  return 0;
}
