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

PHDR_FORMAT = '<2I6Q'
PHDR_ENTRY_FIELDS = ['p_type', 'p_flags', 'p_offset', 'p_vaddr',
                     'p_paddr', 'p_filesz', 'p_memsz', 'p_align']
PT_LOAD = 1
PT_NOTE = 4

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4
PF_MASKPROC = 0xf0000000

SHDR_INVALID_OFFSET = 0
SHDR_FORMAT = '<2I4Q2I2Q'
SHDR_ENTRY_FIELDS = ['sh_name', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset',
					 'sh_size', 'sh_link', 'sh_info', 
					 'sh_addralign', 'sh_entsize']


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
        raw_phdr = raw_phdrs[offset: offset + phentsize]
        phdrs.append(parse_phdr(raw_phdr))
    return phdrs


def parse_phdr(raw_phdr):
    phdr_values = struct.unpack(PHDR_FORMAT, raw_phdr)
    return collect_struct_fields(PHDR_ENTRY_FIELDS, phdr_values)


def parse_shdrs(ehdr, file_content):
	shoff = ehdr.get('e_shoff')
	shnum = ehdr.get('e_shnum')
	shentsize = ehdr.get('e_shentsize')

	if shoff == SHDR_INVALID_OFFSET:
		return None

	raw_shdrs = file_content[shoff:shoff+(shnum * shentsize)]
	shdrs = []

	for offset in range(0, len(raw_shdrs), shentsize):
		raw_shdr = raw_shdrs[offset:offset+shentsize]
		shdrs.append(parse_shdr(raw_shdr))
	return shdrs


def parse_shdr(raw_shdr):
	shdr_values = struct.unpack(SHDR_FORMAT, raw_shdr)
	return collect_struct_fields(SHDR_ENTRY_FIELDS, shdr_values)


def pack_elf_header(ehdr):
    return struct.pack(ELF_HEADER_FORMAT, *ehdr.values())


def pack_phdrs(phdrs):
    raw_phdrs = b''

    for phdr in phdrs:
        raw_phdrs += struct.pack(PHDR_FORMAT, *phdr.values())
    return raw_phdrs


def pack_shdrs(shdrs):
	raw_shdrs = b''

	for shdr in shdrs:
		raw_shdrs += struct.pack(SHDR_FORMAT, *shdr.values())
	return raw_shdrs


def get_text_phdr(phdrs):
	for phdr in phdrs:
		if phdr['p_type'] == PT_LOAD and phdr['p_flags'] == PF_R | PF_X:
			return phdr
	return None


def get_data_phdr(phdrs):
	for phdr in phdrs:
		if phdr['p_type'] == PT_LOAD and phdr['p_flags'] == PF_R | PF_W:
			return phdr
	return None


def collect_struct_fields(field_names, values):
    od = OrderedDict()
    for field_name, value in zip(field_names, values):
        od[field_name] = value

    return od