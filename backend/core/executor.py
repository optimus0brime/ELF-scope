"""
UnicornExecutor — PLT interception, syscall stubs, pause-on-input, disassembly context.
"""

import struct
from unicorn import (
    Uc, UcError,
    UC_ARCH_X86, UC_MODE_64,
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_INSN,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
)
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP, UC_X86_REG_EFLAGS, UC_X86_INS_SYSCALL,
)
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from .state  import SimulatorState
from .loader import BinaryLoader
from . import libc_stubs

STACK_BASE = 0x7FFFF000
STACK_SIZE = 0x100000
MMAP_ALIGN = 0x1000
STUB_BASE  = 0x7F00001000
STUB_DATA  = 0x7F00003000
STUB_TOTAL = 0x4000
HEAP_BASE  = 0x600000000
HEAP_SIZE  = 0x400000

SYS_READ=0; SYS_WRITE=1; SYS_MMAP=9; SYS_BRK=12
SYS_ARCH_PRCTL=158; SYS_EXIT=60; SYS_EXIT_GROUP=231

REG_MAP = {
    'RAX':UC_X86_REG_RAX,'RBX':UC_X86_REG_RBX,'RCX':UC_X86_REG_RCX,'RDX':UC_X86_REG_RDX,
    'RSI':UC_X86_REG_RSI,'RDI':UC_X86_REG_RDI,'RBP':UC_X86_REG_RBP,'RSP':UC_X86_REG_RSP,
    'R8' :UC_X86_REG_R8, 'R9' :UC_X86_REG_R9, 'R10':UC_X86_REG_R10,'R11':UC_X86_REG_R11,
    'R12':UC_X86_REG_R12,'R13':UC_X86_REG_R13,'R14':UC_X86_REG_R14,'R15':UC_X86_REG_R15,
    'RIP':UC_X86_REG_RIP,
}

def _adn(a): return a & ~(MMAP_ALIGN-1)
def _aup(s,b=0): return (s+b%MMAP_ALIGN+MMAP_ALIGN-1)&~(MMAP_ALIGN-1)


class UnicornExecutor:

    def __init__(self, state: SimulatorState):
        self.state = state
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        self._mapped_ranges: list[tuple[int,int]] = []
        self._stub_map: dict[int,str] = {}

        self.stdin_lines:  list[str] = []
        self.stdout_lines: list[str] = []

        # pause-on-input state
        self.waiting_for_input  = False
        self.pending_input_func = None   # 'gets', 'fgets', 'scanf'
        self.pending_input_args: dict = {}

        # argv passed in at load time
        self.initial_args: list[str] = ['emulator']

        self.heap_top    = HEAP_BASE
        self.entry_point = 0
        self.binary_info: dict = {}
        self._last_stub_log = None

        self._setup_hooks()

    # ── Hooks ─────────────────────────────────────────────────

    def _setup_hooks(self):
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        self.uc.hook_add(UC_HOOK_CODE,      self._hook_code)
        self.uc.hook_add(UC_HOOK_INSN,      self._hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED,  self._hook_mem_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_fetch_unmapped)

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        try: self.state.set_memory(address, value.to_bytes(size,'little'))
        except Exception: pass

    def _hook_code(self, uc, address, size, user_data):
        if address not in self._stub_map: return
        func_name = self._stub_map[address]
        msg = libc_stubs.dispatch(func_name, uc, self.state, self)
        self._last_stub_log = f'[stub] {msg}'

    def _hook_syscall(self, uc, user_data):
        rax=uc.reg_read(UC_X86_REG_RAX); rdi=uc.reg_read(UC_X86_REG_RDI)
        rsi=uc.reg_read(UC_X86_REG_RSI); rdx=uc.reg_read(UC_X86_REG_RDX)
        if rax == SYS_WRITE:
            if rdi in (1,2):
                try:
                    data=bytes(uc.mem_read(rsi,rdx))
                    self.stdout_lines.append(data.decode('utf-8',errors='replace'))
                except Exception: pass
            uc.reg_write(UC_X86_REG_RAX, rdx)
        elif rax == SYS_READ:
            if rdi==0 and self.stdin_lines:
                line=self.stdin_lines.pop(0)
                data=(line+'\n').encode('utf-8',errors='replace')[:rdx]
                try: uc.mem_write(rsi,data); self.state.set_memory(rsi,data)
                except Exception: data=b''
                uc.reg_write(UC_X86_REG_RAX,len(data))
            elif rdi==0 and not self.stdin_lines:
                # Pause
                self.waiting_for_input=True
                self.pending_input_func='read'
                self.pending_input_args={'buf':rsi,'count':rdx}
                uc.emu_stop(); return
            else: uc.reg_write(UC_X86_REG_RAX,0)
        elif rax == SYS_BRK:
            if rdi==0: uc.reg_write(UC_X86_REG_RAX,self.heap_top)
            else:
                self.heap_top=max(self.heap_top,rdi)
                uc.reg_write(UC_X86_REG_RAX,self.heap_top)
        elif rax == SYS_MMAP:
            ptr=self.heap_alloc(rsi); uc.reg_write(UC_X86_REG_RAX,ptr)
        elif rax in (SYS_EXIT,SYS_EXIT_GROUP):
            code=rdi&0xFF
            self.stdout_lines.append(f'[exit({code})]\n')
            self.state.halted=True; self.state.halt_reason=f'exit({code})'
            uc.reg_write(UC_X86_REG_RAX,0)
        elif rax==SYS_ARCH_PRCTL: uc.reg_write(UC_X86_REG_RAX,0)
        else: uc.reg_write(UC_X86_REG_RAX,0xFFFFFFFFFFFFFFDA)
        self.state.set_register('RAX',uc.reg_read(UC_X86_REG_RAX))

    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        page=_adn(address)
        try: uc.mem_map(page,MMAP_ALIGN); self._mapped_ranges.append((page,MMAP_ALIGN)); return True
        except Exception: return False

    def _hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        if address==0 or address<=0x1000:
            self.state.halted=True; self.state.halt_reason='Program returned (exited normally)'
        else:
            self.state.halted=True
            self.state.halt_reason=f'UC_ERR_FETCH_UNMAPPED at 0x{address:016x}'
        return False

    # ── Binary loading ─────────────────────────────────────────

    def load_binary(self, binary_path: str):
        info=BinaryLoader.load(binary_path)
        self.binary_info=info; self.entry_point=info['entry_point']
        self._last_stub_log=None; self.waiting_for_input=False

        for seg in info['segments']:
            vaddr=seg['vaddr']; memsz=seg['memsz']; data=seg['data']
            base=_adn(vaddr); size=_aup(memsz,vaddr)
            if not self._is_mapped(base,size):
                self.uc.mem_map(base,size); self._mapped_ranges.append((base,size))
            if data: self.uc.mem_write(vaddr,data); self.state.set_memory(vaddr,data)

        for base,size in [((_adn(STACK_BASE-STACK_SIZE)),STACK_SIZE),(STUB_BASE,STUB_TOTAL),(HEAP_BASE,HEAP_SIZE)]:
            if not self._is_mapped(base,size):
                self.uc.mem_map(base,size); self._mapped_ranges.append((base,size))

        # Build argv in stub data area
        argv0=b'/emulator\x00'; args=self.initial_args or ['emulator']
        arg_ptrs=[]; offset=0
        for a in args:
            ab=(a+'\x00').encode()
            self.uc.mem_write(STUB_DATA+offset,ab); self.state.set_memory(STUB_DATA+offset,ab)
            arg_ptrs.append(STUB_DATA+offset); offset+=len(ab)
        arg_ptrs.append(0)  # NULL terminator
        argv_arr=struct.pack(f'<{len(arg_ptrs)}Q',*arg_ptrs)
        argv_ptr=STUB_DATA+0x100
        self.uc.mem_write(argv_ptr,argv_arr); self.state.set_memory(argv_ptr,argv_arr)
        self._argv_ptr=argv_ptr; self._argc=len(args)

        rsp=STACK_BASE-8
        self.uc.mem_write(rsp,struct.pack('<Q',0))  # sentinel
        frame=struct.pack('<QQQQ',len(args),argv_ptr,0,0)
        frame_addr=rsp-len(frame)
        self.uc.mem_write(frame_addr,frame)

        for reg,val in [('RIP',self.entry_point),('RSP',frame_addr),('RBP',frame_addr)]:
            self.state.set_register(reg,val)
            self.uc.reg_write(REG_MAP[reg],val)

        self._setup_plt_stubs(binary_path)

    def _setup_plt_stubs(self, binary_path: str):
        from elftools.elf.elffile import ELFFile
        try:
            with open(binary_path,'rb') as f:
                elf=ELFFile(f)
                dynsym=elf.get_section_by_name('.dynsym')
                if not dynsym: return
                relocs=[]; 
                for sn in ('.rela.plt','.rela.dyn'):
                    s=elf.get_section_by_name(sn)
                    if s: relocs.append(s)
                if not relocs: return
                idx=0; seen=set()
                for sec in relocs:
                    for rel in sec.iter_relocations():
                        if rel['r_info_type'] not in (6,7): continue
                        sym=dynsym.get_symbol(rel['r_info_sym'])
                        if not sym or not sym.name: continue
                        got_addr=rel['r_offset']
                        if got_addr in seen: continue
                        seen.add(got_addr)
                        stub_addr=STUB_BASE+idx*8
                        self.uc.mem_write(stub_addr,b'\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC')
                        try:
                            self.uc.mem_write(got_addr,stub_addr.to_bytes(8,'little'))
                            self.state.set_memory(got_addr,stub_addr.to_bytes(8,'little'))
                        except Exception: pass
                        self._stub_map[stub_addr]=sym.name; idx+=1
        except Exception: pass

    # ── Heap ──────────────────────────────────────────────────

    def heap_alloc(self, size: int, zero: bool=False) -> int:
        aligned=(size+15)&~15; ptr=self.heap_top; self.heap_top+=aligned
        page=_adn(ptr); end=_aup(aligned,ptr)
        for p in range(page,page+end,MMAP_ALIGN):
            if not self._is_mapped(p,MMAP_ALIGN):
                try: self.uc.mem_map(p,MMAP_ALIGN); self._mapped_ranges.append((p,MMAP_ALIGN))
                except Exception: pass
        if zero:
            try: self.uc.mem_write(ptr,bytes(size)); self.state.set_memory(ptr,bytes(size))
            except Exception: pass
        return ptr

    # ── Single step ───────────────────────────────────────────

    def execute_one_instruction(self) -> dict:
        if self.state.halted:
            return {'error':'Halted','halted':True,'halt_reason':self.state.halt_reason}
        if self.waiting_for_input:
            return {'waiting_for_input':True,'pending_func':self.pending_input_func,'new_output':[]}

        rip=self.state.get_register('RIP'); self._last_stub_log=None
        raw=self.state.get_memory(rip,15)
        instrs=list(self.cs.disasm(raw,rip))
        if not instrs and rip in self._stub_map:
            instrs=list(self.cs.disasm(b'\xC3',rip))
        if not instrs:
            self.state.halted=True
            self.state.halt_reason=f'Cannot disassemble at 0x{rip:016x} (bytes: {raw[:4].hex()})'
            return {'error':self.state.halt_reason,'halted':True}

        instr=instrs[0]
        snap_before=self.state.get_snapshot()
        regs_before=dict(self.state.registers); flags_before=dict(self.state.flags)
        stdout_before=len(self.stdout_lines)

        try:
            self.uc.emu_start(rip,rip+instr.size,timeout=0,count=1)
        except UcError as e:
            if not self.state.halted and not self.waiting_for_input:
                self.state.halted=True
                self.state.halt_reason=f'Unicorn: {e} at 0x{rip:016x} ({instr.mnemonic} {instr.op_str})'
            new_out=self.stdout_lines[stdout_before:]
            if self.waiting_for_input:
                return {'waiting_for_input':True,'pending_func':self.pending_input_func,
                        'instruction':{'address':f'0x{rip:016x}','mnemonic':instr.mnemonic,
                                       'op_str':instr.op_str,'bytes':instr.bytes.hex(),'size':instr.size},
                        'new_output':new_out,'stub_log':self._last_stub_log}
            return {'error':self.state.halt_reason,'halted':True,
                    'halt_reason':self.state.halt_reason,
                    'instruction':{'address':f'0x{rip:016x}','mnemonic':instr.mnemonic,
                                   'op_str':instr.op_str,'bytes':instr.bytes.hex(),'size':instr.size},
                    'new_output':new_out,'stub_log':self._last_stub_log}

        self._sync_from_unicorn()
        regs_after=dict(self.state.registers); flags_after=dict(self.state.flags)
        changed_regs=SimulatorState.diff_registers(regs_before,regs_after)
        changed_flags=SimulatorState.diff_flags(flags_before,flags_after)

        m=instr.mnemonic.lower()
        if m=='call': self.state.push_call(rip,regs_after['RIP'])
        elif m=='ret':
            self.state.pop_call()
            if regs_after['RIP']<=0x1000:
                self.state.halted=True; self.state.halt_reason='Program returned (exited normally)'

        self.state.record_instruction(rip,instr.mnemonic,instr.op_str,
                                      regs_before,regs_after,flags_before,flags_after)
        new_out=self.stdout_lines[stdout_before:]
        return {
            'success':True,'halted':self.state.halted,'halt_reason':self.state.halt_reason,
            'instruction':{'address':f'0x{rip:016x}','bytes':instr.bytes.hex(),
                           'mnemonic':instr.mnemonic,'op_str':instr.op_str,'size':instr.size},
            'state_before':snap_before,'state_after':self.state.get_snapshot(),
            'changed_registers':changed_regs,'changed_flags':changed_flags,
            'new_output':new_out,'stub_log':self._last_stub_log,
        }

    # ── Resume after waiting_for_input ───────────────────────

    def resume_from_input(self, input_text: str) -> dict:
        """Complete a paused gets/fgets/scanf call and return a step result."""
        if not self.waiting_for_input:
            return {'error':'Not waiting for input'}

        func=self.pending_input_func; args=self.pending_input_args
        buf_addr=args.get('buf_addr',0) or args.get('buf',0)
        rip=self.state.get_register('RIP')

        self.stdout_lines.append(input_text+'\n')  # echo

        if func in ('gets','fgets','read'):
            max_len=args.get('max_len',args.get('count',4096))
            data=(input_text[:max_len-1]+'\n' if func=='fgets' else input_text).encode('utf-8',errors='replace')+b'\x00'
            try:
                self.uc.mem_write(buf_addr,data); self.state.set_memory(buf_addr,data)
                self.uc.reg_write(UC_X86_REG_RAX,buf_addr); self.state.set_register('RAX',buf_addr)
            except Exception as e:
                self.waiting_for_input=False
                return {'error':f'resume write failed: {e}','halted':False,'new_output':[]}

        elif func=='scanf':
            self.stdin_lines.insert(0,input_text)
            self.uc.reg_write(UC_X86_REG_RAX,1); self.state.set_register('RAX',1)

        # Simulate the RET instruction the stub was paused at
        rsp=self.uc.reg_read(UC_X86_REG_RSP)
        try:
            ret_addr=struct.unpack('<Q',bytes(self.uc.mem_read(rsp,8)))[0]
            self.uc.reg_write(UC_X86_REG_RSP,rsp+8); self.uc.reg_write(UC_X86_REG_RIP,ret_addr)
            self.state.set_register('RSP',rsp+8);   self.state.set_register('RIP',ret_addr)
        except Exception as e:
            self.waiting_for_input=False
            return {'error':f'resume RET simulation failed: {e}','halted':False,'new_output':[]}

        self.waiting_for_input=False; self.pending_input_func=None; self.pending_input_args={}
        new_out=list(self.stdout_lines); self.stdout_lines.clear()
        rip_after=self.state.get_register('RIP')
        return {
            'success':True,'halted':False,'halt_reason':None,'waiting_for_input':False,
            'instruction':{'address':f'0x{rip_after:016x}','bytes':'',
                           'mnemonic':f'[{func}() resumed]','op_str':f'"{input_text[:30]}"','size':0},
            'state_after':self.state.get_snapshot(),
            'changed_registers':[],'changed_flags':[],'new_output':new_out,'stub_log':None,
        }

    # ── Disassembly context ───────────────────────────────────

    def disasm_at(self, address: int, count: int=20) -> list:
        """Disassemble up to count instructions starting at address."""
        try:
            raw=bytes(self.uc.mem_read(address,count*15))
        except Exception:
            raw=self.state.get_memory(address,count*15)
        result=[]
        for ins in self.cs.disasm(raw,address):
            result.append({'address':f'0x{ins.address:016x}','bytes':ins.bytes.hex(),
                           'mnemonic':ins.mnemonic,'op_str':ins.op_str,'size':ins.size})
            if len(result)>=count: break
        return result

    # ── Helpers ───────────────────────────────────────────────

    def _sync_from_unicorn(self):
        for n,c in REG_MAP.items(): self.state.set_register(n,self.uc.reg_read(c))
        self.state.set_rflags(self.uc.reg_read(UC_X86_REG_EFLAGS))

    def _is_mapped(self,base,size):
        return any(base<s+z and base+size>s for s,z in self._mapped_ranges)

    def set_register(self,name,value):
        if name not in REG_MAP: raise ValueError(f'Unknown: {name}')
        self.state.set_register(name,value); self.uc.reg_write(REG_MAP[name],value&0xFFFFFFFFFFFFFFFF)

    def read_memory(self,address,size):
        try: return bytes(self.uc.mem_read(address,size))
        except UcError: return self.state.get_memory(address,size)

    def get_binary_info(self): return self.binary_info
    def get_stub_map(self): return {f'0x{a:016x}':n for a,n in self._stub_map.items()}
