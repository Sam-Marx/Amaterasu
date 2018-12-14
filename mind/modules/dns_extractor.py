#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

def dns_ex():
	target = input('Enter URL: ')
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