#coding: utf-8
#!/usr/bin/python3

from huepy import *
import tldextract
import ipaddress
import requests
import socket
import json
import sys

def ip_locator_CONFIG():
	target = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('ip_locator')) + ')' + '> ')
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
					print(bold(info('Target:\t\t' + target)))
				elif user.split(' ')[1] == 'options':
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
				else:
					print(bold(bad('Error: option do not exist.')))
			except IndexError:
				print(bold(info('Select what to show.\n')))
				print(bold(info('Config\t\tshow config')))
				print(bold(info('Options\t\tshow options')))
		elif user.startswith('run'):
			try:
				iplocator(target)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def iplocator(target):
	if target.startswith('http://') or target.startswith('https://'):
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix

		target = domain + '.' + suffix
	else:
		pass
	target = socket.gethostbyname(target)
	r = requests.get('https://ipapi.co/' + target + '/json/')
	n = r.text
	jsons = json.loads(n)
	print()
	print(bold(green('IP: ')) + str(jsons['ip']))
	print(bold(green('City: ')) + str(jsons['city']))
	print(bold(green('Region: ')) + str(jsons['region']))
	print(bold(green('Region Code: ')) + str(jsons['region_code']))
	print(bold(green('Country: ')) + str(jsons['country_name']))
	print(bold(green('Country Code: ')) + str(jsons['country']))
	print(bold(green('Postal: ')) + str(jsons['postal']))
	print(bold(green('Latitude: ')) + str(jsons['latitude']))
	print(bold(green('Longitude: ')) + str(jsons['longitude']))
	print(bold(green('Timezone: ')) + str(jsons['timezone']))
	print(bold(green('UTC offset: ')) + str(jsons['utc_offset']))
	print(bold(green('Country calling code: ')) + str(jsons['country_calling_code']))
	print(bold(green('Currency: ')) + str(jsons['currency']))
	print(bold(green('Languages: ')) + str(jsons['languages']))
	print(bold(green('ASN: ')) + str(jsons['asn']))
	print(bold(green('Organization: ')) + str(jsons['org']))
	print(bold(green('Aditional info:')))
	if ipaddress.ip_address(target).is_multicast == True:
		print('\t' + bold(good('The IP is reserved for multicast use.')))
	if ipaddress.ip_address(target).is_private == True:
		print('\t' + bold(good('The IP is allocated for public networks.')))
	if ipaddress.ip_address(target).is_global == True:
		print('\t' + bold(good('The IP is allocated for private networks.')))
