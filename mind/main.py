#coding: utf-8
#!/usr/bin/python3

#MAIN
from mind.modules.BruteforceImports import * #Importing Bruteforce modules
from mind.modules.InformationGatheringImports import * #Importing Information Gathering modules
from mind.modules.NetworkImports import * #Importing Network modules
from mind.modules.Exploitation import * #Importing Exploitation modules

from core.main_update import *
from core.main_clear import *
from core.main_show import *
from core.banner import *

from ruamel.yaml import YAML
from huepy import *
import sys
import os

from core.main_clear import *
from core.checkErrors import *

def main():
	show_help()
	import_file = open('core/import.yaml').read()
	yaml = YAML()
	importE = yaml.load(import_file) #import error
	bruteforce = importE['BRUTEFORCE']
	informationG = importE['INFORMATION_GATHERING']
	exploitation = importE['EXPLOITATION']
	network = importE['NETWORK']

	try:
		while True:
			user = input(bold(red('\nAMATERASU ') + '> '))
			if user.startswith('use'):
				try:
					if user.split(' ')[1] == 'network_mapper':
						if network[0]['network_mapper'].startswith('Pass'):
							try:
								network_mapper_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'whois_extractor':
						if informationG[7]['whois_extractor'].startswith('Pass'):
							try:
								whois_extractor_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'email_extractor':
						if informationG[0]['email_extractor'].startswith('Pass'):
							try:
								email_extractor_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'metadata_extractor':
						if informationG[3]['metadata_extractor'].startswith('Pass'):
							try:
								metadata_extractor_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'reverse_ip':
						if network[1]['reverse_ip'].startswith('Pass'):
							try:
								reverse_ip_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'iplocator':
						if network[2]['iplocator'].startswith('Pass'):
							try:
								ip_locator_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'spider':
						if informationG[6]['spider'].startswith('Pass'):
							try:
								spider_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'dns_extractor':
						if network[3]['dns_extractor'].startswith('Pass'):
							try:
								dns_extractor_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'ftp_bruteforce':
						if bruteforce[0]['ftp_bruteforce'].startswith('Pass'):
							try:
								ftp_bruteforce_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'panelfinder':
						if bruteforce[0]['panelfinder'].startswith('Pass'):
							try:
								login_panel_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'ssh_bruteforce':
						if bruteforce[0]['ssh_bruteforce'].startswith('Pass'):
							try:
								ssh_bruteforce_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'honeypot_detector':
						if informationG[1]['honeypot_detector'].startswith('Pass'):
							try:
								honeypot_detector_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'gmail_bruteforce':
						if bruteforce[0]['gmail_bruteforce'].startswith('Pass'):
							try:
								gmail_bruteforce_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'num_verify':
						if informationG[4]['num_verify'].startswith('Pass'):
							try:
								num_verify_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'mysql_vuln_scanner':
						if informationG[5]['mysql_vuln_scanner'].startswith('Pass'):
							try:
								mysql_vuln_scanner_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'ipwhois_extractor':
						if informationG[2]['ipwhois_extractor'].startswith('Pass'):
							try:
								ipwhois_extractor_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					elif user.split(' ')[1] == 'atgworm':
						if exploitation[0]['atgworm'].startswith('Pass'):
							try:
								atgworm_CONFIG()
							except KeyboardInterrupt:
								print()
								main()
						else:
							print(bold(bad('Install all modules to use.')))
					else:
						print(bold(bad('Module not found.')))
				except Exception as e:
					pass

			elif user.startswith('set'):
				try:
					config_file = open('core/config.yaml').read()
					yaml = YAML()
					config = yaml.load(config_file)
					api = config['API']

					if user.split(' ')[1] == 'shodan_api':
						api[0]['Shodan'] = user.split(' ')[2]
						print(bold(info('Shodan API set:\t' + user.split(' ')[2])))
						with open('core/config.yaml', 'w') as cf:
							yaml.dump(config, cf)
						cf.close()

					elif user.split(' ')[1] == 'censys_uid':
						api[1]['Censys UID'] = user.split(' ')[2]
						print(bold(info('Censys UID set:\t' + user.split(' ')[2])))
						with open('core/config.yaml', 'w') as cf:
							yaml.dump(config, cf)
						cf.close()

					elif user.split(' ')[1] == 'censys_secret':
						api[2]['Censys SECRET'] = user.split(' ')[2]
						print(bold(info('Censys SECRET set:\t' + user.split(' ')[2])))
						with open('core/config.yaml', 'w') as cf:
							yaml.dump(config, cf)
						cf.close()

					elif user.split(' ')[1] == 'numverify_api':
						api[3]['Numverify'] = user.split(' ')[2]
						print(bold(info('Numverify API set:\t' + user.split(' ')[2])))
						with open('core/config.yaml', 'w') as cf:
							yaml.dump(config, cf)
						cf.close()
					else:
						print(bold(bad('Command not found.')))

				except IndexError:
					show_SET_OPTIONS()
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
					elif user.split(' ')[1] == 'history':
						show_history()
					else:
						print(bold(bad('Option not found.')))
				except IndexError:
					show_SHOW_OPTIONS()

			elif user == 'exit':
				print(bold(good('Thanks for using Amaterasu.')))

				sys.exit()
			elif user == 'cls' or user == 'clear':
				clear()
			elif user == 'update':
				update()
			elif user == 'author':
				author()
			elif user == '?' or user == 'help':
				show_help()
			elif user == 'exec':
				exec(user.split(''))
			else:
				print(bold(bad('Command not found.')))
	except KeyboardInterrupt:
		print()
		print(bad('"exit" to get out.'))
		print()
