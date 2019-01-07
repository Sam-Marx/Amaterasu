#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

def whois_extractor_CONFIG():
	target = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('WHOIS_extractor')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					if target.endswith('.txt'):
						print(bold(info('Target list set: ' + target)))
					else:
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
					if target.endswith('.txt'):
						print(bold(info('Target list:\t\t' + target)))
					else:
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
				whois_extractor(target)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def whois_extractor(target):
	try:
		if target.endswith('.txt'):
			filelist = open(target, 'r')

			for domain in filelist.readlines():
				domain = domain.strip()
				addr = socket.gethostbyname(domain)
				obj = IPWhois(addr)
				res = obj.lookup()

				whname = res["nets"][0]['name']
				whdesc = res["nets"][0]['description']
				whemail = res["nets"][0]['abuse_emails']
				whcount = res["nets"][0]['country']
				whstate = res["nets"][0]['state']
				whcidr = res["nets"][0]['cidr']
				whcity = res["nets"][0]['city']
				whadd = res["nets"][0]['address']
				whasncidr = res['asn_cidr']
				whasn = res['asn']
				whasndt = res['asn_date']
				whasnreg = res['asn_registry']

				print()
				print(bold(green('Domain: ')) + domain)
				if whname == None:
					pass
				else:
					print(bold(green('Name: ' )) + whname)
				print(bold(green('IP: ')) + addr)
				if whdesc == None:
					pass
				else:
					print(bold(green('Description: ')) + whdesc)
				if whcount == None:
					pass
				else:
					print(bold(green("Country: ")) + whcount)
				if whstate == None:
					pass
				else:
					print(bold(green('State: ')) + whstate)
				if whcity == None:
					pass
				else:
					print(bold(green('City: ')) + whcity)
				if whadd == None:
					pass
				else:
					print(bold(green('Address: ')) + whadd)
				if whemail == None:
					pass
				else:
					print(bold(green('Abuse e-mail: ')) + whemail)
				if whcidr == None:
					pass
				else:
					print(bold(green('CIDR: ')) + whcidr)
				if whasncidr == None:
					pass
				else:
					print(bold(green('ASN CIDR: ')) + whasncidr)
				if whasn == None:
					pass
				else:
					print(bold(green('ASN: ')) + whasn)

		elif target.startswith('http://') or target.startswith('https://'):
			ext = tldextract.extract(target)
			domain = ext.domain
			suffix = ext.suffix

			fullsite = domain + '.' + suffix

			addr = socket.gethostbyname(fullsite)
			obj = IPWhois(addr)
			res = obj.lookup()

			whname = res["nets"][0]['name']
			whdesc = res["nets"][0]['description']
			whemail = res["nets"][0]['abuse_emails']
			whcount = res["nets"][0]['country']
			whstate = res["nets"][0]['state']
			whcidr = res["nets"][0]['cidr']
			whcity = res["nets"][0]['city']
			whadd = res["nets"][0]['address']
			whasncidr = res['asn_cidr']
			whasn = res['asn']
			whasndt = res['asn_date']
			whasnreg = res['asn_registry']

			print()
			if whname == None:
				pass
			else:
				print(bold(green('Name: ' )) + whname)
			if whdesc == None:
				pass
			else:
				print(bold(green('Description: ')) + whdesc)
			if whcount == None:
				pass
			else:
				print(bold(green("Country: ")) + whcount)
			if whstate == None:
				pass
			else:
				print(bold(green('State: ')) + whstate)
			if whcity == None:
				pass
			else:
				print(bold(green('City: ')) + whcity)
			if whadd == None:
				pass
			else:
				print(bold(green('Address: ')) + whadd)
			if whemail == None:
				pass
			else:
				print(bold(green('Abuse e-mail: ')) + whemail)
			if whcidr == None:
				pass
			else:
				print(bold(green('CIDR: ')) + whcidr)
			if whasncidr == None:
				pass
			else:
				print(bold(green('ASN CIDR: ')) + whasncidr)
			if whasn == None:
				pass
			else:
				print(bold(green('ASN: ')) + whasn)
		else:
			addr = socket.gethostbyname(target)
			obj = IPWhois(addr)
			res = obj.lookup()

			whname = res["nets"][0]['name']
			whdesc = res["nets"][0]['description']
			whemail = res["nets"][0]['abuse_emails']
			whcount = res["nets"][0]['country']
			whstate = res["nets"][0]['state']
			whcidr = res["nets"][0]['cidr']
			whcity = res["nets"][0]['city']
			whadd = res["nets"][0]['address']
			whasncidr = res['asn_cidr']
			whasn = res['asn']
			whasndt = res['asn_date']
			whasnreg = res['asn_registry']

			print()
			if whname == None:
				pass
			else:
				print(bold(green('Name: ' )) + whname)
			if whdesc == None:
				pass
			else:
				print(bold(green('Description: ')) + whdesc)
			if whcount == None:
				pass
			else:
				print(bold(green("Country: ")) + whcount)
			if whstate == None:
				pass
			else:
				print(bold(green('State: ')) + whstate)
			if whcity == None:
				pass
			else:
				print(bold(green('City: ')) + whcity)
			if whadd == None:
				pass
			else:
				print(bold(green('Address: ')) + whadd)
			if whemail == None:
				pass
			else:
				print(bold(green('Abuse e-mail: ')) + whemail)
			if whcidr == None:
				pass
			else:
				print(bold(green('CIDR: ')) + whcidr)
			if whasncidr == None:
				pass
			else:
				print(bold(green('ASN CIDR: ')) + whasncidr)
			if whasn == None:
				pass
			else:
				print(bold(green('ASN: ')) + whasn)
	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))
