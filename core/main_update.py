#coding: utf-8
#!/usr/bin/python3

from core.main_imports import *

version = '1.3'

def update():
	r = requests.get('https://raw.githubusercontent.com/SamCEAP/Amaterasu/master/core/current_release.txt')
	if float(r.text) > float(version):
		print(bold(info('Current version: ' + version)))
		print(bold(info('Amaterasu can be updated. New version: ' + r.text)))
		if platform.system() == 'Windows':
			print(bold(bad('Amaterasu needs to be updated manually.')))
		else:
			os.system('git clone --depth=1 https://github.com/SamCEAP/Amaterasu.git')
			os.system('cd Amaterasu')
			os.system('python3 amaterasu.py')
	else:
		print(bold(good('Amaterasu is updated.')))
