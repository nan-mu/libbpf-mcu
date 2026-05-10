#include <stdio.h>
#include "inclued/vmlinux.h"
#include "inclued/linux/if_ether.h"

int main() {
    printf("sizeof(struct ethhdr) = %zu\n", sizeof(struct ethhdr));
    printf("sizeof(struct iphdr) = %zu\n", sizeof(struct iphdr));
    printf("sizeof(struct udphdr) = %zu\n", sizeof(struct udphdr));
    return 0;
}
