#coding: utf-8
#!/usr/bin/python3

import platform
import os

#clear
def clear():
	if platform.system() == 'Windows':
		os.system('cls')
	else:
		os.system('clear')
