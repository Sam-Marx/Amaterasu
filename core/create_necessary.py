#coding: utf-8
#!/usr/bin/python3

from core.main_imports import *

def create_necessary():
	try:
		if os.path.isdir('E-mails') == True:
			pass
		else:
			p = pathlib.Path('E-mails/')
			p.mkdir(parents=True)
			print(bold(info('Created ' + bold(lightred('E-mails ')) + 'directory.')))
		if os.path.isdir('Links') == True:
			pass
		else:
			p = pathlib.Path('Links/')
			p.mkdir(parents=True)
			print(bold(info('Created ' + bold(lightred('Links ')) + 'directory.')))
		if os.path.isdir('Subdomains') == True:
			pass
		else:
			p = pathlib.Path('Subdomains/')
			p.mkdir(parents=True)
			print(bold(info('Created ' + bold(lightred('Subdomains ')) + 'directory.')))
		if os.path.isdir('ReverseIP_Domains') == True:
			pass
		else:
			p = pathlib.Path('ReverseIP_Domains/')
			p.mkdir(parents=True)
			print(bold(info('Created ' + bold(lightred('ReverseIP_Domains ')) + 'directory.')))
		print()

	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))
