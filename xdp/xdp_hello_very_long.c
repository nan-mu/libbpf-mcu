#include <bpf_helpers.h>
#include <bpf_endian.h>

SEC("xdp")
int hello_xdp_very_long(void *ctx) {
    static const char msg[] = "This is a very long message to test if the compiler will still inline everything or use memory references instead of immediate values!";
    bpf_helper_log(msg);
    static const char msg2[] = "HI";
    bpf_helper_log(msg2);
    return 42;
}
