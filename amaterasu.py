#coding: utf-8
#!/usr/bin/python3

from core.banner import show_banners
from mind.main import main, clear
from time import *
from huepy import *

versao = '0.2.1'

def show_info():
	import os
	import platform

	name = os.name
	os = platform.system()
	system = platform.release()

	print(bold(green('[+] ')) + 'Operating System detected: ' + bold(red(name)) + ', ' + bold(red(os)) + ' ' + bold(red(system)) + '.')
	print(bold(green('\t\tWelcome to AMATERASU.')))

if __name__ == '__main__':
	try:
		clear()
		show_banners(versao)
		print('''
		{}
		{}
		{}
		'''.format(bold(red('AMATERASU')), bold(purple('PENETRATION TESTING FRAMEWORK')), 'v' + versao))
		sleep(0.4)
		show_info()
		while True:
			main()

	except Exception as e:
		print(bad('Exception: {}'.format(e)))
