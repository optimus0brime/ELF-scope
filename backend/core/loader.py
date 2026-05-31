"""
BinaryLoader — parses x86-64 ELF binaries using pyelftools.

Responsibility is limited to reading the file and returning structured
metadata. Actual memory mapping into Unicorn is done by UnicornExecutor;
this loader just tells it what to map and where.
"""

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class BinaryLoader:

    @staticmethod
    def load(binary_path: str) -> dict:
        """
        Parse an ELF binary and return a metadata dict containing:
          - entry_point: the virtual address where execution starts
          - segments:    list of PT_LOAD segments to map into memory
          - sections:    named sections (.text, .data, .bss, etc.)
          - symbols:     symbol table if present (function names, addresses)
          - arch:        e_machine string for validation
        """
        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)

            # Validate this is actually x86-64
            if elf.get_machine_arch() != 'x64':
                raise ValueError(
                    f"Expected x86-64 ELF, got: {elf.get_machine_arch()}"
                )

            return {
                'entry_point': elf.header['e_entry'],
                'arch':        elf.get_machine_arch(),
                'segments':    BinaryLoader._load_segments(elf),
                'sections':    BinaryLoader._load_sections(elf),
                'symbols':     BinaryLoader._load_symbols(elf),
            }

    @staticmethod
    def _load_segments(elf) -> list:
        """
        Extract all PT_LOAD segments — these are the parts of the binary
        that the OS (or emulator) must actually map into virtual memory.
        Each segment has a virtual address, raw data, and permission flags.
        """
        segments = []
        for seg in elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            segments.append({
                'vaddr':  seg['p_vaddr'],
                'paddr':  seg['p_paddr'],
                'filesz': seg['p_filesz'],
                'memsz':  seg['p_memsz'],    # may be larger (e.g. .bss is zero-filled)
                'flags':  seg['p_flags'],    # R=4, W=2, X=1
                'align':  seg['p_align'],
                'data':   seg.data(),        # raw bytes from file
            })
        return segments

    @staticmethod
    def _load_sections(elf) -> list:
        """Named sections — useful for the UI to show .text address, etc."""
        sections = []
        for sec in elf.iter_sections():
            if sec.name == '' or sec['sh_type'] == 'SHT_NULL':
                continue
            sections.append({
                'name':    sec.name,
                'address': sec['sh_addr'],
                'size':    sec['sh_size'],
                'type':    sec['sh_type'],
            })
        return sections

    @staticmethod
    def _load_symbols(elf) -> list:
        """
        Extract the symbol table if one exists. This lets us show function
        names next to addresses in the UI (e.g. "main", "printf@plt").
        Many stripped binaries have no symbol table — that's fine.
        """
        symbols = []
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym.name and sym['st_value'] != 0:
                    symbols.append({
                        'name':    sym.name,
                        'address': sym['st_value'],
                        'size':    sym['st_size'],
                        'type':    sym['st_info']['type'],
                    })
        return symbols
