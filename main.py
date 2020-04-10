#! /usr/bin/python3
import argparse
import struct

from ELF.elf import Elf
from infections.silvio_padding import SilvioPaddingInfector


FILE_NAME_ARG = 'file_name'


def parse_args():
    parser = argparse.ArgumentParser(description='Parse a ELF file ELF header.')
    parser.add_argument('file_name', type=str, help='The given ELF file-name.')
    args = parser.parse_args()
    return vars(args)


def main():
    arguments = parse_args()

    f = open(arguments.get(FILE_NAME_ARG), 'rb')
    elf_obj = Elf(f)
    infector = SilvioPaddingInfector()
    infector.infect(elf_obj, 'new_simple', b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    f.close()
   
if __name__=='__main__':
	main()