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

ARCH_64_BIT = 2
DATA_2_LSB = 1

PHDR_FORMAT = '<2I6Q'
PHDR_ENTRY_FIELDS = ['p_type', 'p_flags', 'p_offset', 'p_vaddr',
                     'p_paddr', 'p_filesz', 'p_memsz', 'p_align']


class Elf(object):

    def __init__(self, file):
        self.file_content = file.read()
        elf_header = self.file_content[:ELF_HEADER_LEN]
        
        self._parse_elf_header(elf_header)
        self._parse_phdrs()

    def _parse_elf_header(self, elf_header):
        ehdr_values = struct.unpack(ELF_HEADER_FORMAT, elf_header)
        self.ehdr = collect_struct_fields(ELF_HEADER_FIELDS, ehdr_values)

    def _parse_phdrs(self):
        phoff = self.ehdr.get('e_phoff')
        phnum = self.ehdr.get('e_phnum')
        phentsize = self.ehdr.get('e_phentsize')

        phdrs = self.file_content[phoff:phoff+(phentsize * phnum)]
        self.phdrs = []

        for offset in range(0, len(phdrs), phentsize):
            phdr = phdrs[offset: offset + phentsize]
            self.phdrs.append(self._parse_phdr(phdr))

    def _parse_phdr(self, phdr):
        phdr_values = struct.unpack(PHDR_FORMAT, phdr)
        return collect_struct_fields(PHDR_ENTRY_FIELDS, phdr_values)

    def save_as(self, file_name):
        raw_elf_header = self._pack_elf_header()
        content = raw_elf_header + self.file_content[ELF_HEADER_LEN:]

        with open(file_name, 'wb') as new_file:
            new_file.write(content)

    def _pack_elf_header(self):
        return struct.pack(ELF_HEADER_FORMAT, *self.ehdr.values())

def collect_struct_fields(field_names, values):
    od = OrderedDict()

    for field_name, value in zip(field_names, values):
        od[field_name] = value

    return od