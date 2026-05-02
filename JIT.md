lw      a1, 0x0(a0)
lw      a2, 0x4(a0)
addi    a3, a1, 0xe
li      a0, 0x2
bltu    a2, a3, 0xa <xdp_firewall+0xa>
addi    sp, sp, -0x20
sw      ra, 0x1c(sp)
sw      s0, 0x18(sp)
lbu     a4, 0xd(a1)
lbu     a5, 0xc(a1)
slli    a4, a4, 0x8
or      a4, a4, a5
li      a5, 0x8
bne     a4, a5, 0x22 <xdp_firewall+0x22>
addi    a4, a1, 0x22
bltu    a2, a4, 0x2a <xdp_firewall+0x2a>
lbu     a4, 0x0(a3)
andi    a5, a4, 0xf
li      s0, 0x5
bltu    a5, s0, 0x38 <xdp_firewall+0x38>
slli    a5, a5, 0x2
add     a3, a3, a5
bgeu    a2, a3, 0x40 <xdp_firewall+0x40>
li      a0, 0x0
lw      ra, 0x1c(sp)
lw      s0, 0x18(sp)
addi    sp, sp, 0x20
ret
lbu     a3, 0x17(a1)
li      a5, 0x11
bne     a3, a5, 0x46 <xdp_firewall+0x46>
slli    a4, a4, 0x1c
srli    a0, a4, 0x1a
add     a0, a0, a1
addi    a3, a0, 0x16
bltu    a2, a3, 0x64 <xdp_firewall+0x64>
lw      a1, 0x1a(a1)
lhu     a0, 0x10(a0)
sw      a1, 0x10(sp)
sw      a0, 0x14(sp)
lui     a0, 0x0
mv      a0, a0
addi    a1, sp, 0x10
auipc   ra, 0x0
jalr    ra <xdp_firewall+0x7e>
beqz    a0, 0x86 <xdp_firewall+0x86>
lbu     a0, 0x0(a0)
beqz    a0, 0x8c <xdp_firewall+0x8c>
sw      zero, 0xc(sp)
lui     a0, 0x0
mv      a0, a0
addi    a1, sp, 0xc
auipc   ra, 0x0
jalr    ra <xdp_firewall+0x9a>
mv      a2, a0
li      a0, 0x1
beqz    a2, 0xa6 <xdp_firewall+0xa6>
li      s0, 0x1
j       0xaa <xdp_firewall+0xaa>
li      a0, 0x1
sw      a0, 0xc(sp)
lui     a0, 0x0
mv      a0, a0
addi    a1, sp, 0xc
auipc   ra, 0x0
jalr    ra <xdp_firewall+0xba>
mv      a2, a0
li      a0, 0x2
beqz    a2, 0xc6 <xdp_firewall+0xc6>
li      s0, 0x2
li      a1, 0x1
li      a3, 0x5
mv      a0, a2
li      a2, 0x0
auipc   ra, 0x0
jalr    ra <xdp_firewall+0xd2>
mv      a0, s0
j       0xdc <xdp_firewall+0xdc>