#coding: utf-8
#!/usr/bin/python3

from ruamel.yaml import YAML
from huepy import *
import requests
import json
import sys

def num_verify_CONFIG():
	target = ''
	country_code = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('number_verify')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					print(bold(info('Target set: ' + target)))
				elif user.split(' ')[1] == 'country_code' or user.split(' ')[1] == 'COUNTRY_CODE':
					country_code = user.split(' ')[2]
					print(bold(info('Country code set: ' + user)))
				else:
					print(bold(bad('Error: option do not exist.')))
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('country code\tset country_code COUNTRY_CODE')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
				print(bold(info('country code\tset country_code COUNTRY_CODE')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print()
					sConfig = {'Target': target,
					'Country code': country_code}
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
					sOptions = {'Target': 'set target TARGET',
					'Country code': 'set country_code COUNTRY_CODE'}
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
				num_verify(target, country_code)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'set target [TARGET]',
			'set country_code': 'set country_code [COUNTRY_CODE]',
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
		else:
			print(bold(bad('Command not found.')))

def num_verify(target, country_code):
	config_file = open('core/config.yaml').read()
	yaml = YAML()
	config = yaml.load(config_file)
	api = config['API']

	numverify_api = api[3]['Numverify']
	print()

	try:
		r = requests.get('http://apilayer.net/api/validate?access_key={}&number={}&country_code={}&format=1'.format(numverify_api, target, country_code))
		jsons = json.loads(r.text)
		print(bold(green('Valid: ')) + str(jsons['valid']))
		print(bold(green('Number: ')) + str(jsons['number']))
		print(bold(green('Local format: ')) + str(jsons['local_format']))
		print(bold(green('International format: ')) + str(jsons['international_format']))
		print(bold(green('Country prefix: ')) + str(jsons['country_prefix']))
		print(bold(green('Country code: ')) + str(jsons['country_code']))
		print(bold(green('Country name: ')) + str(jsons['country_name']))
		print(bold(green('Location: ')) + str(jsons['location']))
		print(bold(green('Carrier: ')) + str(jsons['carrier']))
		print(bold(green('Line type: ')) + str(jsons['line_type']))
	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))	
