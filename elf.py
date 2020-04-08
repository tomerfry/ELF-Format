import struct

EI_NIDENT = 16
IDENT_STRUCT_FORMAT = '<4x5b7x'
ELF_MAGIC = '\x7fELF'
ELF_MAGIC_LEN = 4


class Elf(object):

    def __init__(self, file):
        if self.is_elf_file(file):
            self.file = file
        else:
            raise AttributeError('Not an Elf file')
        
        self.parse_ident(file)

    def parse_ident(self, file):
        ident = file.read(EI_NIDENT)
        ident_values = struct.unpack(IDENT_STRUCT_FORMAT, ident)
        arch, data, version, os_abi, abi_version = ident_values
        self.arch = arch
        self.data = data
        self.version = version
        self.os_abi = os_abi
        self.abi_version = abi_version

    @staticmethod
    def is_elf_file(file):
        ident = file.read(ELF_MAGIC_LEN)
        return ELF_MAGIC == ident

    @staticmethod
    def parse_elf_header(file, arch):
        return {}
