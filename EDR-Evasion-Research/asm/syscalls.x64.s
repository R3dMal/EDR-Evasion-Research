.data
    .align 4
    wSSN:        .long 0
    qSyscallAddr:.quad 0

.text
    .globl SetSyscallEntry
    .globl DoSyscall

SetSyscallEntry:
    movl %ecx, wSSN(%rip)
    movq %rdx, qSyscallAddr(%rip)
    ret

DoSyscall:
    movq %rcx, %r10
    movl wSSN(%rip), %eax
    jmp *qSyscallAddr(%rip)
