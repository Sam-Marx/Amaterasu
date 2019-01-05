#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *
from mind.main import *

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
				dns_extractor(target)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
			banner()
			main()
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def dns_extractor(target):
	dnsr = dns.resolver

	if target.startswith('https://') or target.startswith('http://'):
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix

		target = domain + '.' + suffix

		try:
			print()
			ns = dnsr.query(target, 'NS')
			for rs in ns:
				print(bold(green('NS records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > NS records.'))

		try:
			print()
			a = dnsr.query(target, 'A')
			for rs in a:
				print(bold(green('A records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > A records.'))

		try:
			print()
			mx = dnsr.query(target, 'MX')
			for rs in mx:
				print(bold(green('MX records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > MX records.'))

		try:
			print()
			txt = dnsr.query(target, 'TXT')
			for spf in txt:
				print(bold(green('SPF records: ')) + str(spf))
		except dns.exception.DNSException:
			print(bad('Query failed > SPF records.'))

	else:
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix

		target = domain + '.' + suffix

		try:
			print()
			ns = dnsr.query(target, 'NS')
			for rs in ns:
				print(bold(green('NS records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > NS records.'))

		try:
			print()
			a = dnsr.query(target, 'A')
			for rs in a:
				print(bold(green('A records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > A records.'))

		try:
			print()
			mx = dnsr.query(target, 'MX')
			for rs in mx:
				print(bold(green('MX records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > MX records.'))

		try:
			print()
			txt = dnsr.query(target, 'TXT')
			for spf in txt:
				print(bold(green('SPF records: ')) + str(spf))
		except dns.exception.DNSException:
			print(bad('Query failed > SPF records.'))
