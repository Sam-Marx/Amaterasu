#coding: utf-8
#!/usr/bin/python3

#MAIN
from mind.modules.BruteforceImports import * #Importing Bruteforce modules
from mind.modules.InformationGatheringImports import * #Importing Information Gathering modules
from mind.modules.NetworkImports import * #Importing Network modules

from core.main_update import *
from core.main_clear import *
from core.main_show import *
from core.banner import *

from ruamel.yaml import YAML
from huepy import *
import sys
import os

def main():
	show_help()
	try:
		while True:
			user = input(bold(red('\nAMATERASU ' + '> ')))
			if user.startswith('use'):
				try:
					if user.split(' ')[1] == 'network_mapper':
						try:
							network_mapper_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'whois_extractor':
						try:
							whois_extractor_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'email_extractor':
						try:
							email_extractor_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'metadata_extractor':
						try:
							metadata_extractor_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'reverse_ip':
						try:
							reverse_ip_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'iplocator':
						try:
							ip_locator_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'spider':
						try:
							spider_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'subdomain':
						try:
							subdomain()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'dns_extractor':
						try:
							dns_extractor_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'ftp_bruteforce':
						try:
							ftp_bruteforce_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'panelfinder':
						try:
							login_panel_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'ssh_bruteforce':
						try:
							ssh_bruteforce_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'honeypot_detector':
						try:
							honeypot_detector_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'gmail_bruteforce':
						try:
							gmail_bruteforce_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'num_verify':
						try:
							num_verify_CONFIG()
						except KeyboardInterrupt:
							print()
							main()
				except IndexError:
					show_module()
					print(bold(info('Select a module.')))

			elif user.startswith('set'):
				try:
					config_file = open('core/config.yaml').read()
					yaml = YAML()
					config = yaml.load(config_file)
					api = config['API']

					if user.split(' ')[1] == 'shodan_api':
						api[0]['Shodan'] = user.split(' ')[2]
						print(bold(info('Shodan API\t' + user.split(' ')[2])))
						with open('core/config.yaml', 'w') as cf:
							yaml.dump(config, cf)
						cf.close()

					elif user.split(' ')[1] == 'censys_uid':
						api[1]['Censys UID'] = user.split(' ')[2]
						print(bold(info('Censys UID\t' + user.split(' ')[2])))
						with open('core/config.yaml', 'w') as cf:
							yaml.dump(config, cf)
						cf.close()

					elif user.split(' ')[1] == 'censys_secret':
						api[2]['Censys SECRET'] = user.split(' ')[2]
						print(bold(info('Censys SECRET\t' + user.split(' ')[2])))
						with open('core/config.yaml', 'w') as cf:
							yaml.dump(config, cf)
						cf.close()

					elif user.split(' ')[1] == 'numverify_api':
						api[3]['Numverify'] = user.split(' ')[2]
						print(bold(info('Numverify API\t' + user.split(' ')[2])))
						with open('core/config.yaml', 'w') as cf:
							yaml.dump(config, cf)
						cf.close()

				except IndexError:
					print(bold(info('Select what to set\n')))
					print(bold(info('API KEY\t\tset (shodan_api|censys_uid|censys_secret) API_KEY')))
				except Exception as e:
					print(bold(bad('Error: {}'.format(str(e)))))
					main()
				except KeyboardInterrupt:
					print()
					main()

			elif user.startswith('show'):
				try:
					if user.split(' ')[1] == 'modules':
						show_module()
					elif user.split(' ')[1] == 'author':
						author()
					elif user.split(' ')[1] == 'banners' or user.split(' ')[1] == 'banner':
						show_banners()
					elif user.split(' ')[1] == 'help':
						show_help()
					elif user.split(' ')[1] == 'apis':
						show_API()
				except IndexError:
					print(bold(info('Select what to show.\n')))
					print(bold(info('Modules\t\tshow modules')))
					print(bold(info('Author\t\tshow author')))
					print(bold(info('Banners\t\tshow banners')))
					print(bold(info('Help\t\tshow help')))
					print(bold(info('API\t\t\tshow apis')))

			elif user == 'exit':
				print(bold(good('Thanks for using Amaterasu.')))
				sys.exit()
			elif user == 'cls' or user == 'clear':
				clear()
			elif user == 'update':
				update()
			elif user == 'author':
				author()
			elif user == '?':
				show_help()
			else:
				print(bad('Amaterasu could not understand.'))
	except KeyboardInterrupt:
		print()
		print(bad('"exit" to get out.'))
		print()
