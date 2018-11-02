#coding: utf-8
#!/usr/bin/python3

from core.banner import banner
from mind.main import main, clear
from time import *
from huepy import *

versao = '0.0.4'

def show_info():
	import os
	import platform

	name = os.name
	os = platform.system()
	system = platform.release()

	print(bold(green('[+] ')) + 'Operating System detected: ' + bold(red(name)) + ', ' + bold(red(os)) + ' ' + bold(red(system)) + '.')
	print(bold(green('\n 		Welcome to AMATERASU.		\n')))

if __name__ == '__main__':
	try:
		clear()
		banner(versao)
		sleep(0.5)
		show_info()
		while True:
			main()

	except Exception as e:
		print(bad('Exception: {}'.format(e)))
