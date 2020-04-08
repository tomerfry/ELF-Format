import struct
from collections import namedtuple

EI_NIDENT = 16
IDENT_FORMAT = '<4s5b7x'

ELF_MAGIC = b'\x7fELF'
ELF_MAGIC_LEN = 4

ARCH_64_BIT = 2
DATA_2_LSB = 1

ELF_HEADER_FORMAT = '<16x2HI3QI6H'
ELF_HEADER_LEN = struct.calcsize(ELF_HEADER_FORMAT)

PHDR_FORMAT = '<2I6Q'

class Elf(object):

    def __init__(self, file):
        self.file_content = file.read()
        elf_header = self.file_content[:ELF_HEADER_LEN]
        
        self._parse_elf_header(elf_header)
        self._parse_phdrs()

    def _parse_elf_header(self, elf_header):
        e_header_values = struct.unpack(ELF_HEADER_FORMAT, elf_header)

        e_ident = self._parse_ident(elf_header)
        e_type, e_machine, e_version, e_entry, e_phoff,\
         e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,\
         e_shentsize, e_shnum, e_shstrndx = e_header_values

        self.e_header = {
        'e_ident': e_ident,
        'e_type': e_type,
        'e_machine': e_machine,
        'e_version': e_version,
        'e_entry': e_entry,
        'e_phoff': e_phoff,
        'e_shoff': e_shoff,
        'e_flags': e_flags,
        'e_ehsize': e_ehsize,
        'e_phentsize': e_phentsize,
        'e_phnum': e_phnum,
        'e_shentsize': e_shentsize,
        'e_shnum': e_shnum,
        'e_shstrndx': e_shstrndx
        }

    def _parse_ident(self, elf_header):
        ident = elf_header[:EI_NIDENT]
        ident_values = struct.unpack(IDENT_FORMAT, ident)
        
        ei_magic, ei_class, ei_data, ei_version,\
         ei_osabi, ei_abiversion = ident_values
        
        if ei_class != ARCH_64_BIT or ei_data != DATA_2_LSB:
            raise ValueError('Unsupported ELF file.')
        if ei_magic != ELF_MAGIC:
            raise ValueError('Not an ELF file.')

        self.e_ident = {
        'ei_magic': ei_magic,
        'ei_class': ei_class,
        'ei_data': ei_data,
        'ei_version': ei_version,
        'ei_osabi': ei_osabi,
        'ei_abiversion': ei_abiversion
        }

    def _parse_phdrs(self):

        phoff = self.e_header.get('e_phoff')
        phnum = self.e_header.get('e_phnum')
        phentsize = self.e_header.get('e_phentsize')

        phdrs = self.file_content[phoff:phoff+(phentsize * phnum)]
        self.phdrs = []

        for offset in range(0, len(phdrs), phentsize):
            phdr = phdrs[offset: offset + phentsize]
            self.phdrs.append(self._parse_phdr(phdr))


    def _parse_phdr(self, phdr):
        phdr_values = struct.unpack(PHDR_FORMAT, phdr)
        
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,\
         p_align = phdr_values

        return {
        'p_type': p_type,
        'p_flags': p_flags,
        'p_offset': p_offset,
        'p_vaddr': p_vaddr,
        'p_paddr': p_paddr,
        'p_filesz': p_filesz,
        'p_memsz': p_memsz,
        'p_align': p_align
        }

