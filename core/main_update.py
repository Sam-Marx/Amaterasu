#coding: utf-8
#!/usr/bin/python3

from core.main_imports import *

def update():
	if platform.system() == 'Windows':
		print(bold(bad('Amaterasu cant be updated in Windows OS.')))
	else:
		os.system('git clone --depth=1 https://github.com/SamCEAP/Amaterasu.git')
		os.system('cd Amaterasu')
		os.system('python3 amaterasu.py')
