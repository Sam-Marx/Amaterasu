#coding: utf-8
#!/usr/bin/python3

from huepy import *
import requests
import dns.resolver
import pathlib
import tldextract
import dns.query
import dns.zone
import sys
import os

def dns_extractor_CONFIG():
	target = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('dns_extractor')) + ')' + '> ')
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
					sOptions = {'Target': 'set target [TARGET]'}
					print(bold('COMMAND\t\t\tDESCRIPTION'))
					print(bold('-------\t\t\t-----------'))
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
				dns_extractor(target)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'target [TARGET]',
			'run':'execute module',
			'back':'back to menu',
			'exit':'quit from Amaterasu'}
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

def dns_extractor(target):
	dnsr = dns.resolver

	ext = tldextract.extract(target)
	domain = ext.domain
	suffix = ext.suffix

	target = domain + '.' + suffix

	try:
		print()
		ns = dnsr.query(target, 'NS')
		for rs in ns:
			print(bold(green('DNS records: ')) + str(rs))
	except dns.exception.DNSException:
		print(bold(bad('Query failed with NS records.')))

	try:
		print()
		a = dnsr.query(target, 'A')
		for rs in a:
			print(bold(green('Host records: ')) + str(rs))
	except dns.exception.DNSException:
		print(bold(bad('Query failed with A records.')))

	try:
		print()
		mx = dnsr.query(target, 'MX')
		for rs in mx:
			print(bold(green('MX records: ')) + str(rs))
	except dns.exception.DNSException:
		print(bold(bad('Query failed with MX records.')))

	try:
		print()
		txt = dnsr.query(target, 'TXT')
		for spf in txt:
			print(bold(green('SPF records: ')) + str(spf))
	except dns.exception.DNSException:
		print(bold(bad('Query failed with SPF records.')))

	if os.path.isdir('Results/' + target) is False:
		p = pathlib.Path('Results/' + target)
		p.mkdir(parents=True)
	else: pass
	try:
		resp = requests.get('https://dnsdumpster.com/static/map/{}.png'.format(target))
		if resp.status_code == 200:
			with open('Results/' + target + '/' + target + '_dns' + '.jpg', 'wb') as f:
				f.write(resp.content)
			print()
			print(bold(info('dnsdumpster.com image result saved.')))
		else: pass
	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))
