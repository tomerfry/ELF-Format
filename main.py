#! /usr/bin/python
import argparse
from elf import Elf

FILE_NAME_ARG = 'file_name'

def parse_args():
    parser = argparse.ArgumentParser(description='Parse a ELF file ELF header.')
    parser.add_argument('file_name', type=str, help='The given ELF file-name.')
    args = parser.parse_args()
    return dict(args)

def main():
    arguments = parse_args()

    with open(arguments.get(FILE_NAME_ARG), 'rb') as f:
        try:
            elf_obj = Elf(f)
        except AttributeError as e:
            print('Error: {}'.format(str(e)))
            
        print(elf_obj.elf_header)


if __name__=='__main__':
	main()