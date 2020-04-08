import struct
from collections import OrderedDict

from elf_utils import *



class Elf(object):

    def __init__(self, file):
        self.file_content = file.read()
        elf_header = self.file_content[:ELF_HEADER_LEN]
        
        self.ehdr = parse_elf_header(elf_header)
        self.phdrs = parse_phdrs(self.ehdr, self.file_content)

    def save_as(self, file_name):
        raw_elf_header = pack_elf_header(self.ehdr)
        raw_phdrs = pack_phdrs(self.phdrs)

        with open(file_name, 'wb') as new_file:
            new_file.write(self.file_content)
            new_file.seek(0)
            new_file.write(raw_elf_header)
            new_file.seek(self.ehdr.get('e_phoff'))
            new_file.write(raw_phdrs)