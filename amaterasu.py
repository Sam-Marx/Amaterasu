#coding: utf-8
#!/usr/bin/python3

from core.create_necessary import create_necessary
from core.banner import show_banners
from mind.main import main, clear
from time import *
from huepy import *
import requests

version = open('core/current_release.txt', 'r')
version = version.read()

new_version = requests.get('https://raw.githubusercontent.com/Sam-Marx/Amaterasu/master/core/current_release.txt')

def show_info():
	import os
	import platform

	name = os.name
	os = platform.system()
	system = platform.release()

	print(bold(green('[+] ')) + 'Operating System detected: ' + bold(red(name)) + ', ' + bold(red(os)) + ' ' + bold(red(system)) + '.')
	if float(new_version.text) > float(version):
		print(bold(good('Amaterasu can be updated. New version: ' + str(new_version.text))))

	print(bold(green('\tWelcome to AMATERASU.')))

if __name__ == '__main__':
	try:
		clear()
		show_banners()
		print('''
		{}
	{}
		{}
		'''.format(bold(red('AMATERASU')), bold(purple('PENETRATION TESTING FRAMEWORK')), 'v' + version))
		create_necessary()
		sleep(0.4)
		show_info()
		while True:
			main()

	except Exception as e:
		print(bad('Exception: {}'.format(e)))
