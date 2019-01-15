#coding: utf-8
#!/usr/bin/python3

import os
from huepy import *
import pathlib

def create_necessary():
	try:
		if os.path.isdir('Results') == True:
			pass
		else:
			p = pathlib.Path('Results/')
			p.mkdir(parents=True)
			print(bold(info('Created ' + bold(lightred('Results ')) + 'directory.')))
		print()

	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))
