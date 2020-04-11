from infections.infector import Infector
from ELF.elf import Elf
from ELF.elf_utils import get_text_phdr
from mmap import PAGESIZE

def page_round(length):
	return length + (length % PAGESIZE) 

class ReverseTextInfector(Infector):

	def infect(self, elf_obj, infected_name, payload)
		pass