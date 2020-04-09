import struct
from collections import OrderedDict

ELF_HEADER_FORMAT = '<4s5b7x2HI3QI6H'
ELF_HEADER_LEN = struct.calcsize(ELF_HEADER_FORMAT)
ELF_HEADER_FIELDS = ['ei_magic', 'ei_class', 'ei_data', 'ei_version',
                        'ei_osabi', 'ei_abiversion', 'e_type', 'e_machine',
                        'e_version', 'e_entry', 'e_phoff', 'e_shoff', 
                        'e_flags', 'e_ehsize', 'e_phentsize', 'e_phnum', 
                        'e_shentsize', 'e_shnum', 'e_shstrndx']

ELF_MAGIC = b'\x7fELF'
ELF_MAGIC_LEN = 4

CLASS_ARCH_64 = 2
DATA_2_LSB = 1

PHDR_FORMAT = '<2I6Q'
PHDR_ENTRY_FIELDS = ['p_type', 'p_flags', 'p_offset', 'p_vaddr',
                     'p_paddr', 'p_filesz', 'p_memsz', 'p_align']


def parse_elf_header(raw_ehdr):
    ehdr_values = struct.unpack(ELF_HEADER_FORMAT, raw_ehdr)
    ehdr = collect_struct_fields(ELF_HEADER_FIELDS, ehdr_values)
    return ehdr

def parse_phdrs(ehdr, file_content):
    phoff = ehdr.get('e_phoff')
    phnum = ehdr.get('e_phnum')
    phentsize = ehdr.get('e_phentsize')

    raw_phdrs = file_content[phoff:phoff+(phentsize * phnum)]
    phdrs = []

    for offset in range(0, len(raw_phdrs), phentsize):
        phdr = raw_phdrs[offset: offset + phentsize]
        phdrs.append(parse_phdr(phdr))
    return phdrs

def parse_phdr(raw_phdr):
    phdr_values = struct.unpack(PHDR_FORMAT, raw_phdr)
    return collect_struct_fields(PHDR_ENTRY_FIELDS, phdr_values)

def pack_elf_header(ehdr):
    return struct.pack(ELF_HEADER_FORMAT, *ehdr.values())

def pack_phdrs(phdrs):
    raw_phdrs = b''

    for phdr in phdrs:
        raw_phdrs += struct.pack(PHDR_FORMAT, *phdr.values())
    return raw_phdrs

def collect_struct_fields(field_names, values):
    od = OrderedDict()
    for field_name, value in zip(field_names, values):
        od[field_name] = value

    return od