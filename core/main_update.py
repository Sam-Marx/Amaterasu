#coding: utf-8
#!/usr/bin/python3

import requests
import platform
import os
from huepy import *

version = open('core/current_release.txt', 'r')
version = version.read()

def update():
	r = requests.get('https://raw.githubusercontent.com/Sam-Marx/Amaterasu/master/core/current_release.txt')
	if float(r.text) > float(version):
		print(bold(info('Current version: ' + version)))
		print(bold(info('Amaterasu can be updated. New version: ' + r.text)))
		if platform.system() == 'Windows':
			print(bold(bad('Amaterasu needs to be updated manually.')))
		else:
			if os.getcwd().endswith('Amaterasu'):
				os.system('cd ..')
				os.system('rm -rf Amaterasu/')
				os.system('git clone --depth=1 https://github.com/Sam-Marx/Amaterasu.git')
				os.system('cd Amaterasu')
				os.system('python3 amaterasu.py')
			else:
				os.system('rm -rf Amaterasu/')
				os.system('git clone --depth=1 https://github.com/Sam-Marx/Amaterasu.git')
				os.system('cd Amaterasu')
				os.system('python3 amaterasu.py')
	else:
		print(bold(good('Amaterasu is updated.')))
