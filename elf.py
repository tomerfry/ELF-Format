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


class Elf(object):

    def __init__(self, file):
        self.file = file
        elf_header = self.file.read(ELF_HEADER_LEN)

        self.e_ident = self.parse_ident(elf_header)
        self.e_header = self.parse_elf_header(elf_header)

    @staticmethod
    def parse_elf_header(elf_header):
        e_header_values = struct.unpack(ELF_HEADER_FORMAT, elf_header)

        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = e_header_values

        return {
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

    @staticmethod
    def parse_ident(elf_header):
        ident = elf_header[:EI_NIDENT]
        ident_values = struct.unpack(IDENT_FORMAT, ident)
        ei_magic, ei_class, ei_data, ei_version, ei_osabi, ei_abiversion = ident_values
        
        if ei_class != ARCH_64_BIT or ei_data != DATA_2_LSB:
            raise AttributeError('Unsupported ELF file.')
        if ei_magic != ELF_MAGIC:
            raise AttributeError('Not an ELF file.')

        return {
        'ei_magic': ei_magic,
        'ei_class': ei_class,
        'ei_data': ei_data,
        'ei_version': ei_version,
        'ei_osabi': ei_osabi,
        'ei_abiversion': ei_abiversion
        }