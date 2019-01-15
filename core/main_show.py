#coding: utf-8
#!/usr/bin/python3

#from core.main_imports import *
from ruamel.yaml import YAML
from huepy import *

#show help
def show_help():
	print()
	sHelp = {'help':'print this help message.',
	'exit':'exit amaterasu',
	'use (MODULE)':'use a module',
	'show (apis|modules)':'show modules or APIs',
	'clear':'clear terminal',
	'update':'update amaterasu',
	'author':'about author of amaterasu'}

	print(bold('COMMAND\t\t\tDESCRIPTION'))
	print(bold('-------\t\t\t-----------'))
	for a, b in sHelp.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))

#show modules
def show_module():
	bruteforceModules = {'ftp_bruteforce':'Bruteforce FTP',
	'ssh_bruteforce':'Bruteforce SSH',
	'gmail_bruteforce':'Bruteforce Gmail',
	'panelfinder':'bruteforce dirs to find login panels'}
	print()

	print(bold(green('Bruteforce modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION'))
	print(bold('-------\t\t\t-----------'))
	for a, b in bruteforceModules.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))
	print()

	###

	networkModules = {'iplocator':'get ip location',
	'reverse_ip':'ip domain lookup',
	'dns_extractor':'extract dns records',
	'network_mapper': 'map network with nmap'}
	print(bold(green('Network modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION'))
	print(bold('-------\t\t\t-----------'))
	for a, b in networkModules.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))
	print()
	
	###

	informationGatheringModules = {'email_extractor':'extract e-mail address',
	'number_extractor': 'extract phone numbers',
	'number_verify': 'verify number information',
	'whois_extractor': 'get whois information',
	'metadata_extractor': 'extract metadata from files',
	'spider': 'extract links from domains',
	'subdomain': 'discover subdomains',
	'mysql_scanner': 'scan website for mysql error based',
	'honeypot_detector':'scan ip for honeypot (needs shodan)'}

	print(bold(green('Information gathering modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION'))
	print(bold('-------\t\t\t-----------'))
	for a, b in informationGatheringModules.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))
	print()

	exploitatonModules = {'mysql_exploiter':'exploit website with mysql error based'}
	print(bold(green('Exploitation modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION'))
	print(bold('-------\t\t\t-----------'))
	for a, b in exploitatonModules.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))
	print()

	postExploitationModules = {'msfvenom_backdoor':'use msfvenom for backdoor creation'}
	print(bold(green('Post exploitation modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION'))
	print(bold('-------\t\t\t-----------'))
	for a, b in postExploitationModules.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))
	print()

#author
def author():
	print()
	print(bold(lightred('About the author.')))
	print(bold('Author: Sam Marx'))
	print(bold('Github: https://github.com/SamCEAP/'))
	print(bold('Twitter: https://twitter.com/Sam_Mrx'))

#show APIs
def show_API():
	print()
	config_file = open('core/config.yaml').read()
	yaml = YAML()
	config = yaml.load(config_file)
	api = config['API']
	print(bold(info('Shodan API:    {}'.format(api[0]['Shodan']))))
	print(bold(info('Censys UID:    {}'.format(api[1]['Censys UID']))))
	print(bold(info('Censys SECRET: {}'.format(api[2]['Censys SECRET']))))
	print(bold(info('Numverify API: {}'.format(api[3]['Numverify']))))
