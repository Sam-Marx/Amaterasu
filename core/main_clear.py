#coding: utf-8
#!/usr/bin/python3

from core.main_imports import *

#clear
def clear():
	if platform.system() == 'Windows':
		os.system('cls')
	else:
		os.system('clear')
