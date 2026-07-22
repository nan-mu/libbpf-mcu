#ifndef __BPF_STRING_H__
#define __BPF_STRING_H__

// 简单的 memset 实现
static inline void *memset(void *s, int c, unsigned long n)
{
    unsigned char *p = s;
    while (n--)
        *p++ = (unsigned char)c;
    return s;
}

// 简单的 memcpy 实现
static inline void *memcpy(void *dest, const void *src, unsigned long n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--)
        *d++ = *s++;
    return dest;
}

#endif /* __BPF_STRING_H__ */
