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
	bruteforceModulesAuthor = {'author':'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx'}

	bruteforceModules = {'ftp_bruteforce':'Bruteforce FTP',
	'ssh_bruteforce':'Bruteforce SSH',
	'gmail_bruteforce':'Bruteforce Gmail',
	'panelfinder':'bruteforce dirs to find login panels'}
	print()

	print(bold(green('Bruteforce modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION\t\t\t\tAUTHOR'))
	print(bold('-------\t\t\t-----------\t\t\t\t------'))
	for c, d in bruteforceModulesAuthor.items():
		for a, b in bruteforceModules.items():
			if len(b) > 20:
				print(bold(a + '\t\t' + b + '\t' + d))
			elif len(b) >= 16 and len(b) < 20:
				print(bold(a + '\t' + b + '\t\t\t' + d))
			elif len(b) >= 14 and len(b) < 16:
				print(bold(a + '\t\t' + b + '\t\t\t\t' + d))
			elif len(b) <= 6:
				print(bold(a + '\t\t' + b + '\t\t\t' + d))
			else:
				print(bold(a + '\t\t' + b + '\t\t\t' + d))
	print()

	###
	networkModulesAuthor = {'author':'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx'}

	networkModules = {'iplocator':'get ip location',
	'reverse_ip':'ip domain lookup',
	'dns_extractor':'extract dns records',
	'network_mapper': 'map network with nmap'}

	print(bold(green('Network modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION\t\t\t\tAUTHOR'))
	print(bold('-------\t\t\t-----------\t\t\t\t------'))
	for c, d in networkModulesAuthor.items():
		for a, b in networkModules.items():
			if len(b) > 20:
				print(bold(a + '\t\t' + b + '\t\t\t' + d))
			elif len(b) >= 16 and len(b) < 20:
				print(bold(a + '\t\t' + b + '\t\t\t' + d))
			elif len(b) >= 14 and len(b) < 16:
				print(bold(a + '\t\t' + b + '\t\t\t\t' + d))
			elif len(b) <= 6:
				print(bold(a + '\t\t' + b + '\t\t\t' + d))
			else:
				print(bold(a + '\t\t' + b + '\t\t\t' + d))
	print()
	
	###
	informationGatheringModulesAuthor = {'author':'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx',
	'author': 'Sam Marx'}

	informationGatheringModules = {'email_extractor':'extract e-mail address',
	'number_verify': 'verify number information',
	'whois_extractor': 'get whois information',
	'ipwhois_extractor': 'get ipwhois information',
	'metadata_extractor': 'extract metadata from files',
	'spider': 'extract links from domains',
	'mysql_vuln_scanner': 'scan url for mysql error based vuln',
	'username_checker': 'search for username in some websites',
	'honeypot_detector':'scan ip for honeypot (needs shodan)'}

	print(bold(green('Information gathering modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION\t\t\t\tAUTHOR'))
	print(bold('-------\t\t\t-----------\t\t\t\t------'))
	for c, d in informationGatheringModulesAuthor.items():
		for a, b in informationGatheringModules.items():
			if len(a) >= 15 and len(a) < 16 and len(b) >= 20:
				print(bold(a + '\t\t' + b + '\t\t\t' + d))
			elif len(a) >= 16 and len(a) < 18 and len(b) >= 20 and len(b) <= 25:
				print(bold(a + '\t' + b + '\t\t\t' + d))
			elif len(a) >= 18 and len(a) < 20 and len(b) >= 20 and len(b) <= 25:
				print(bold(a + '\t' + b + '\t\t' + d))
			elif len(a) >= 18 and len(a) < 20 and len(b) >= 25 and len(b) <= 28:
				print(bold(a + '\t' + b + '\t\t' + d))
			elif len(a) >= 16 and len(a) < 20 and len(b) >= 28:
				print(bold(a + '\t' + b + '\t' + d))
			elif len(a) >= 4 and len(a) < 10 and len(b) >= 20:
				print(bold(a + '\t\t\t' + b + '\t\t' + d))
			else:
				print(bold(a + '\t\t' + b + '\t\t' + d))
	print()

	###

	#exploit_name | description | author
	exploitationModulesAuthor = {'author': 'RIS33'}

	exploitationModules = {'atgworm': 'send commands to ATG(s)'}

	print(bold(green('Exploitation modules')))
	print(bold('COMMAND\t\t\tDESCRIPTION\t\t\t\tAUTHOR'))
	print(bold('-------\t\t\t-----------\t\t\t\t------'))
	for c, d in exploitationModulesAuthor.items():
		for a, b in exploitationModules.items():
			if len(b) > 20:
				print(bold(a + '\t\t\t' + b + '\t\t\t' + d))
			elif len(b) >= 16 and len(b) < 20:
				print(bold(a + '\t\t' + b + '\t\t\t' + d))
			elif len(b) >= 14 and len(b) < 16:
				print(bold(a + '\t\t' + b + '\t\t\t\t' + d))
			elif len(a) <= 7:
				print(bold(a + '\t\t\t' + b + '\t\t\t' + d))


#author
def author():
	print()
	print(bold(lightred('About the author.')))
	print(bold('Author: Sam Marx'))
	print(bold('Github: https://github.com/SamCEAP/'))
	print(bold('Twitter: https://twitter.com/Sam_Mrx'))

#show APIs
def show_API():
	#print()
	config_file = open('core/config.yaml').read()
	yaml = YAML()
	config = yaml.load(config_file)
	api = config['API']

	apiKeys = {'Shodan': str(api[0]['Shodan']),
	'Censys UID': str(api[1]['Censys UID']),
	'Censys SECRET': str(api[2]['Censys SECRET']),
	'Numverify': str(api[3]['Numverify'])}

	print()
	print(bold('API\t\t\tKEY'))
	print(bold('---\t\t\t---'))
	for a, b in apiKeys.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))

def show_SET_OPTIONS():
	setOptions = {'shodan_api':'set shodan_api (API-KEY)',
	'censys_uid':'set censys_uid (API-KEY) ',
	'censys_secret':'set censys_secret (API-KEY) ',
	'numverify_api':'set numverify_api (API-KEY)'}

	print()
	print(bold('API\t\t\tCOMMAND'))
	print(bold('---\t\t\t-------'))
	for a, b in setOptions.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))
	print()
	print(bold(white('Select what to set.')))

def show_SHOW_OPTIONS():
	showOptions = {'show modules': 'Modules',
	'show author': 'Author',
	'show banners': 'Banners',
	'show help': 'Help',
	'show apis': 'API'}

	print()
	print(bold('COMMAND\t\t\tDESCRIPTION'))
	print(bold('-------\t\t\t-----------'))
	for a, b in showOptions.items():
		if len(a) > 15:
			print(bold(a + '\t' + b))
		elif len(a) <= 6:
			print(bold(a + '\t\t\t' + b))
		else:
			print(bold(a + '\t\t' + b))
	print()
	print(bold(white('Select what to show.')))
