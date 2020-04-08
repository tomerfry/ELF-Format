import struct

class Elf(object):

    def __init__(self, file):
        if is_elf_file(file):
            self.file = file
        else:
            raise AttributeError('Not an Elf file')
    
        self.elf_header = self.parse_elf_header(file)


    @staticmethod
    def is_elf_file(file):
        file_content = file.read()
        print(file_content[:4])

    @staticmethod
    def parse_elf_header(file):
        return {}
