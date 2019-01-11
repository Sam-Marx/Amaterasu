#coding: utf-8
#!/usr/bin/python3

from core.main_imports import *

def update():
	if platform.system() == 'Windows':
		import urllib.request
		urllib.request.urlretrieve('https://github.com/SamCEAP/Amaterasu/archive/v1.3.zip', 'Amaterasu.zip')
	else:
		os.system('git clone --depth=1 https://github.com/SamCEAP/Amaterasu.git')
		os.system('cd Amaterasu')
		os.system('python3 amaterasu.py')
