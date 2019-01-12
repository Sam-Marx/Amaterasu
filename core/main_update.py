#coding: utf-8
#!/usr/bin/python3

from core.main_imports import *

def update():
	if platform.system() == 'Windows':
		import urllib.request
		try:
			urllib.request.urlretrieve('https://github.com/SamCEAP/Amaterasu/archive/v1.3.zip', 'Amaterasu.zip')
			print(bold(info('Downloaded Amaterasu as Amaterasu.zip.')))
		except Exception as e:
			print(bold(bad('Error: {}'.format(e))))
	else:
		os.system('git clone --depth=1 https://github.com/SamCEAP/Amaterasu.git')
		os.system('cd Amaterasu')
		os.system('python3 amaterasu.py')
