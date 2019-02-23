#coding: utf-8
#!/usr/bin/python3

from ruamel.yaml import YAML
from huepy import *
import requests
import sys

def honeypot_detector_CONFIG():
	target = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('honeypot_detector')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					print(bold(info('Target set: ' + target)))
				else:
					print(bold(bad('Error: option do not exist.')))
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print()
					sConfig = {'Target': target}
					print(bold('CONFIG\t\t\tDESCRIPTION'))
					print(bold('------\t\t\t-----------'))
					for a, b in sConfig.items():
						if len(a) > 15:
							print(bold(a + '\t' + b))
						elif len(a) <= 6:
							print(bold(a + '\t\t\t' + b))
						else:
							print(bold(a + '\t\t' + b))
				elif user.split(' ')[1] == 'options':
					print()
					sOptions = {'Target': 'set target TARGET'}
					print(bold('OPTIONS\t\t\tDESCRIPTION'))
					print(bold('------\t\t\t-----------'))
					for a, b in sOptions.items():
						if len(a) > 15:
							print(bold(a + '\t' + b))
						elif len(a) <= 6:
							print(bold(a + '\t\t\t' + b))
						else:
							print(bold(a + '\t\t' + b))
				else:
					print(bold(bad('Error: option do not exist.')))
			except IndexError:
				print(bold(info('Select what to show.\n')))
				print(bold(info('Config\t\tshow config')))
				print(bold(info('Options\t\tshow options')))
		elif user.startswith('run'):
			try:
				honeypot_detector(target)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'set target [TARGET]',
			'run':'execute module'}
			print()
			print(bold('COMMAND\t\t\tDESCRIPTION'))
			print(bold('-------\t\t\t-----------'))
			for a, b in sHelp.items():
				if len(a) > 15:
					print(bold(a + '\t' + b))
				elif len(a) <= 6:
					print(bold(a + '\t\t\t' + b))
				else:
					print(bold(a + '\t\t' + b))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()
def honeypot_detector(target):
	config_file = open('core/config.yaml').read()
	yaml = YAML()
	config = yaml.load(config_file)
	api = config['API']
	shodan_api = api[0]['Shodan']

	try:
		r = requests.get('https://api.shodan.io/labs/honeyscore/' + target + '?key=' + shodan_api)
		r = r.text
	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))

	if r:
		if float(r) < 0.5:
			print(bold(good('Honeypot probability: ' + r)))
		else:
			print(bold(bad('Honeypot probability: ' + r)))
