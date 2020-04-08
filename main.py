#! /usr/bin/python3
import argparse
import struct

from elf import Elf


FILE_NAME_ARG = 'file_name'


def parse_args():
    parser = argparse.ArgumentParser(description='Parse a ELF file ELF header.')
    parser.add_argument('file_name', type=str, help='The given ELF file-name.')
    args = parser.parse_args()
    return vars(args)

def main():
    arguments = parse_args()

    with open(arguments.get(FILE_NAME_ARG), 'rb') as f:
        try:
            elf_obj = Elf(f)

            elf_obj.save_as('new_simple')
        except ValueError as e:
            print('Error: {}'.format(str(e)))
        except struct.error as e:
            print('Parsing Error: {}'.format(str(e)))


if __name__=='__main__':
	main()