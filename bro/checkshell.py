from __future__ import print_function
from broccoli import *
from unicorn import *
from unicorn.x86_const import *


ADDRESS = 0x1000000

global bc,payload
payload=""
# callback for tracing instructions
def hook_code(uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
        # read this instruction code from memory
        tmp = uc.mem_read(address, size)
        print(">>> Instruction code at [0x%x] =" %(address), end="")
        for i in tmp:
                print(" %02x" %i, end="")
        print("")


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


def hook_intr(uc, intno, user_data):
        global payload
        if intno != 0x80:
                print("got interrupt %x ???" %intno);
                uc.emu_stop()
                return

        eax = uc.reg_read(UC_X86_REG_EAX)
        eip = uc.reg_read(UC_X86_REG_EIP)
        esp = uc.reg_read(UC_X86_REG_ESP)
        if eax == 1:    # sys_exit
                print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" %(eip, intno, eax))
                uc.emu_stop()
        elif eax == 4:  # sys_write
                ecx = uc.reg_read(UC_X86_REG_ECX)
                edx = uc.reg_read(UC_X86_REG_EDX)

                try:
                        buf = uc.mem_read(ecx, edx)
                        print(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = " \
                                                %(eip, intno, ecx, edx), end="")
                        for i in buf:
                                print("%c" %i, end="")
                        print("")
                except UcError as e:
                        print(">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = <unknown>\n" \
                                                %(eip, intno, ecx, edx))
        elif eax == 0xb:        # sys_execv
                ecx = uc.reg_read(UC_X86_REG_ECX)
                edx = uc.reg_read(UC_X86_REG_EDX)
                try:
                        buf = uc.mem_read(esp, 8)
                        print(">>> 0x%x: interrupt 0x%x, SYS_EXECVE.Content = " \
                                                %(eip, intno ), end="")
                        for i in buf:
                                print("%c" %i, end="")
                        print("")
                except UcError as e:
                        print(">>> 0x%x: interrupt 0x%x, SYS_EXECVE.Content = <unknown>\n" \
                                                %(eip, intno))
        else:
                print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" %(eip, intno, eax))


def hook_syscall(mu, user_data):
        global payload
        rax = mu.reg_read(UC_X86_REG_RAX)
        rdi = mu.reg_read(UC_X86_REG_RDI)
        rip = mu.reg_read(UC_X86_REG_RIP)

        if rax == 0x3b: # sys_execv
                try:
                        buf = mu.mem_read(rdi, 8)
                        s=""
                        for i in buf:
                                s+=chr(i)
                        print(s)
                        k = ">>> 0x%x: interrupt 0x%x, SYS_EXECVE .argument =%s"%(rip, rax,s)
                        print (k)
                        bc.send("alert_shellcode",string(payload),string("SYS_EXECVE"),string(s),string(""))
                except UcError as e:
                        k = ">>> 0x%x: interrupt 0x%x .argument =unknow"%(rip, rax)
                        return k
        else:
                k = ">>> 0x%x: interrupt 0x%x"%(rip, rax)
        print(k)
        return k

        mu.emu_stop()



# Test X86 32 bit
def test_i386(mode, code):
        print("Emulate x86 code")
        try:
                # Initialize emulator
                mu = Uc(UC_ARCH_X86, mode)

                # map 2MB memory for this emulation
                mu.mem_map(ADDRESS, 2 * 1024 * 1024)

                # write machine code to be emulated to memory
                mu.mem_write(ADDRESS, code)

                # initialize stack
                mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)

                # tracing all basic blocks with customized callback
                #mu.hook_add(UC_HOOK_BLOCK, hook_block)

                # tracing all instructions with customized callback
                #mu.hook_add(UC_HOOK_CODE, hook_code)

                # handle interrupt ourself
                mu.hook_add(UC_HOOK_INTR, hook_intr)

                # handle SYSCALL
                mu.hook_add(UC_HOOK_INSN, hook_syscall, code, 1, 0, UC_X86_INS_SYSCALL)

                # emulate machine code in infinite time
                mu.emu_start(ADDRESS, ADDRESS + len(code))

                # now print out some registers
                print(">>> Emulation done")

        except UcError as e:
                print("ERROR: %s" % e)

def check_shell(sc):
        #test_i386(UC_MODE_32, sc)
        test_i386(UC_MODE_64, sc)


##########BRO#####################

@event
def is_shellcode(input,do):
        global payload
        print("Input: %s",input)
        payload = input.decode("hex")
        check_shell(payload)
        print("sent")


bc = Connection("127.0.0.1:7331")
print("Unicorn connected to Bro!!!\nGO-->\nGO--> ")
while True:
	bc.processInput();