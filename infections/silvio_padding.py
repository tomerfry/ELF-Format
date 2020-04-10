from infections.infector import Infector
from ELF.elf import Elf


class SilvioPaddingInfector(Infector):

	def infect(self, elf_obj, infected_name):
		print('Infecting using silvio padding.')
