#coding: utf-8
#!/usr/bin/python3

from huepy import *
import socket
import whois
import sys
import tldextract

def whois_extractor_CONFIG():
	target = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('whois_extractor')) + ')' + '> ')
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
				w = whois.whois(domain)

				if type(w.domain_name) is list:
					for dn in w.domain_name:
						print(bold(green('Domain name: ') + str(dn)))
				elif type(w.domain_name) is str:
					print(bold(green('Domain name: ') + str(w.domain_name)))
				else: pass

				if w.name != None:
					print(bold(green('Name: ') + str(w.name)))
				else: pass
				
				if w.org != None:
					print(bold(green('Organization: ') + str(w.org)))
				else: pass

				if w.address != None:
					print(bold(green('Address: ') + str(w.address)))
				else: pass
				
				if w.city != None:
					print(bold(green('City: ') + str(w.city)))
				else: pass
				
				if w.state != None:
					print(bold(green('State: ') + str(w.state)))
				else: pass

				if w.zipcode != None:
					print(bold(green('Zipcode: ') + str(w.zipcode)))
				else: pass

				if w.country != None:
					print(bold(green('Country: ') + str(w.country)))
				else: pass

				if w.owner != None:
					print(bold(green('Owner: ') + str(w.owner)))
				else: pass

				if w.ownerid != None:
					print(bold(green('Owner ID: ') + str(w.ownerid)))
				else: pass

				if w.owner_c != None:
					print(bold(green('Owner_c: ') + str(w.owner_c)))
				else: pass

				if w.admin_c != None:
					print(bold(green('Admin_c: ') + str(w.admin_c)))
				else: pass

				if w.tech_c != None:
					print(bold(green('Tech_c: ') + str(w.tech_c)))
				else: pass

				if w.person != None:
					print(bold(green('Person: ') + str(w.person)))
				else: pass

				if w.registrar != None:
					print(bold(green('Registrar: ') + str(w.registrar)))
				else: pass

				if type(w.updated_date) is list:
					for ud in w.updated_date:
						print(bold(green('Updated date: ') + str(ud)))
				elif type(w.updated_date) is str:
					print(bold(green('Updated date: ') + str(w.updated_date)))
				else: pass

				if type(w.creation_date) is list:
					for cd in w.creation_date:
						print(bold(green('Creation date: ') + str(cd)))
				elif type(w.creation_date) is str:
					print(bold(green('Creation date: ') + str(w.creation_date)))
				else: pass

				if type(w.expiration_date) is list:
					for ed in w.expiration_date:
						print(bold(green('Expiration date: ') + str(ed)))
				elif type(w.expiration_date) is str:
					print(bold(green('Expiration date: ') + str(w.expiration_date)))
				else: pass

				if type(w.name_servers) is list:
					for ns in w.name_servers:
						print(bold(green('Name server: ') + str(ns)))
				elif type(w.name_servers) is str:
					print(bold(green('Name server: ') + str(w.name_servers)))
				else: pass

				if type(w.nserver) is list:
					for ns in w.nserver:
						print(bold(green('Name server: ') + str(ns)))
				elif type(w.nserver) is str:
					print(bold(green('Name server: ') + str(w.nserver)))
				else: pass

				if type(w.emails) is list:
					for email in w.emails:
						print(bold(green('E-mails: ') + str(email)))
				elif type(w.email) is str:
					print(bold(green('E-mail: ') + str(w.email)))
				else: pass

				if w.dnssec != None:
					print(bold(green('Dnssec: ') + str(w.dnssec)))
				else: pass

				if type(w.status) is list:
					for st in w.status:
						print(bold(green('Domain status: ') + str(st)))
				elif type(w.status) is str:
					print(bold(green('Domain status: ') + str(w.status)))
				else: pass
				print()

		elif target.startswith('http://') or target.startswith('https://'):
			ext = tldextract.extract(target)
			domain = ext.domain
			suffix = ext.suffix
			fullsite = domain + '.' + suffix

			w = whois.whois(fullsite)

			if type(w.domain_name) is list:
				for dn in w.domain_name:
					print(bold(green('Domain name: ') + str(dn)))
			elif type(w.domain_name) is str:
				print(bold(green('Domain name: ') + str(w.domain_name)))
			else: pass

			if w.name != None:
				print(bold(green('Name: ') + str(w.name)))
			else: pass
			
			if w.org != None:
				print(bold(green('Organization: ') + str(w.org)))
			else: pass

			if w.address != None:
				print(bold(green('Address: ') + str(w.address)))
			else: pass
			
			if w.city != None:
				print(bold(green('City: ') + str(w.city)))
			else: pass
			
			if w.state != None:
				print(bold(green('State: ') + str(w.state)))
			else: pass

			if w.zipcode != None:
				print(bold(green('Zipcode: ') + str(w.zipcode)))
			else: pass

			if w.country != None:
				print(bold(green('Country: ') + str(w.country)))
			else: pass

			if w.owner != None:
				print(bold(green('Owner: ') + str(w.owner)))
			else: pass

			if w.ownerid != None:
				print(bold(green('Owner ID: ') + str(w.ownerid)))
			else: pass

			if w.owner_c != None:
				print(bold(green('Owner_c: ') + str(w.owner_c)))
			else: pass

			if w.admin_c != None:
				print(bold(green('Admin_c: ') + str(w.admin_c)))
			else: pass

			if w.tech_c != None:
				print(bold(green('Tech_c: ') + str(w.tech_c)))
			else: pass

			if w.person != None:
				print(bold(green('Person: ') + str(w.person)))
			else: pass

			if w.registrar != None:
				print(bold(green('Registrar: ') + str(w.registrar)))
			else: pass

			if type(w.updated_date) is list:
				for ud in w.updated_date:
					print(bold(green('Updated date: ') + str(ud)))
			elif type(w.updated_date) is str:
				print(bold(green('Updated date: ') + str(w.updated_date)))
			else: pass

			if type(w.creation_date) is list:
				for cd in w.creation_date:
					print(bold(green('Creation date: ') + str(cd)))
			elif type(w.creation_date) is str:
				print(bold(green('Creation date: ') + str(w.creation_date)))
			else: pass

			if type(w.expiration_date) is list:
				for ed in w.expiration_date:
					print(bold(green('Expiration date: ') + str(ed)))
			elif type(w.expiration_date) is str:
				print(bold(green('Expiration date: ') + str(w.expiration_date)))
			else: pass

			if type(w.name_servers) is list:
				for ns in w.name_servers:
					print(bold(green('Name server: ') + str(ns)))
			elif type(w.name_servers) is str:
				print(bold(green('Name server: ') + str(w.name_servers)))
			else: pass

			if type(w.nserver) is list:
				for ns in w.nserver:
					print(bold(green('Name server: ') + str(ns)))
			elif type(w.nserver) is str:
				print(bold(green('Name server: ') + str(w.nserver)))
			else: pass

			if type(w.emails) is list:
				for email in w.emails:
					print(bold(green('E-mails: ') + str(email)))
			elif type(w.email) is str:
				print(bold(green('E-mail: ') + str(w.email)))
			else: pass

			if w.dnssec != None:
				print(bold(green('Dnssec: ') + str(w.dnssec)))
			else: pass

			if type(w.status) is list:
				for st in w.status:
					print(bold(green('Domain status: ') + str(st)))
			elif type(w.status) is str:
				print(bold(green('Domain status: ') + str(w.status)))
			else: pass

		else:
			w = whois.whois(target)

			if type(w.domain_name) is list:
				for dn in w.domain_name:
					print(bold(green('Domain name: ') + str(dn)))
			elif type(w.domain_name) is str:
				print(bold(green('Domain name: ') + str(w.domain_name)))
			else: pass

			if w.name != None:
				print(bold(green('Name: ') + str(w.name)))
			else: pass
			
			if w.org != None:
				print(bold(green('Organization: ') + str(w.org)))
			else: pass

			if w.address != None:
				print(bold(green('Address: ') + str(w.address)))
			else: pass
			
			if w.city != None:
				print(bold(green('City: ') + str(w.city)))
			else: pass
			
			if w.state != None:
				print(bold(green('State: ') + str(w.state)))
			else: pass

			if w.zipcode != None:
				print(bold(green('Zipcode: ') + str(w.zipcode)))
			else: pass

			if w.country != None:
				print(bold(green('Country: ') + str(w.country)))
			else: pass

			if w.owner != None:
				print(bold(green('Owner: ') + str(w.owner)))
			else: pass

			if w.ownerid != None:
				print(bold(green('Owner ID: ') + str(w.ownerid)))
			else: pass

			if w.owner_c != None:
				print(bold(green('Owner_c: ') + str(w.owner_c)))
			else: pass

			if w.admin_c != None:
				print(bold(green('Admin_c: ') + str(w.admin_c)))
			else: pass

			if w.tech_c != None:
				print(bold(green('Tech_c: ') + str(w.tech_c)))
			else: pass

			if w.person != None:
				print(bold(green('Person: ') + str(w.person)))
			else: pass

			if w.registrar != None:
				print(bold(green('Registrar: ') + str(w.registrar)))
			else: pass

			if type(w.updated_date) is list:
				for ud in w.updated_date:
					print(bold(green('Updated date: ') + str(ud)))
			elif type(w.updated_date) is str:
				print(bold(green('Updated date: ') + str(w.updated_date)))
			else: pass

			if type(w.creation_date) is list:
				for cd in w.creation_date:
					print(bold(green('Creation date: ') + str(cd)))
			elif type(w.creation_date) is str:
				print(bold(green('Creation date: ') + str(w.creation_date)))
			else: pass

			if type(w.expiration_date) is list:
				for ed in w.expiration_date:
					print(bold(green('Expiration date: ') + str(ed)))
			elif type(w.expiration_date) is str:
				print(bold(green('Expiration date: ') + str(w.expiration_date)))
			else: pass

			if type(w.name_servers) is list:
				for ns in w.name_servers:
					print(bold(green('Name server: ') + str(ns)))
			elif type(w.name_servers) is str:
				print(bold(green('Name server: ') + str(w.name_servers)))
			else: pass

			if type(w.nserver) is list:
				for ns in w.nserver:
					print(bold(green('Name server: ') + str(ns)))
			elif type(w.nserver) is str:
				print(bold(green('Name server: ') + str(w.nserver)))
			else: pass

			if type(w.emails) is list:
				for email in w.emails:
					print(bold(green('E-mails: ') + str(email)))
			elif type(w.email) is str:
				print(bold(green('E-mail: ') + str(w.email)))
			else: pass

			if w.dnssec != None:
				print(bold(green('Dnssec: ') + str(w.dnssec)))
			else: pass

			if type(w.status) is list:
				for st in w.status:
					print(bold(green('Domain status: ') + str(st)))
			elif type(w.status) is str:
				print(bold(green('Domain status: ') + str(w.status)))
			else: pass
			
	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))
