#coding: utf-8
#!/usr/bin/python3
#functions show

from core.main_imports import *

#show help
def show_help():
	print()
	print(bold(info(' Help:					print this help message.')))
	print(bold(info(' Exit:					leave the program.')))
	print(bold(info(' Use:					use module.')))
	print(bold(info(' Show modules:				show modules.')))
	print(bold(info(' Clear:					clear the terminal.')))
	print(bold(info(' Update:					update the framework.')))
	print(bold(info(' Author:					about Amaterasu framework.')))

#check available modules
def checkAvailable(folder):
	q = glob.glob('mind/modules/{}/*.py'.format(folder))
	return(str(int(len(q)) - 1) + str(' modules'))
	
#show modules
def show_module():
	print()
	print(bold(cyan('Bruteforcing ')) + bold(purple('| ')) + bold(cyan(checkAvailable('Bruteforce'))))
	print('	FTP bruteforce 			:		ftp_bruteforce		| Bruteforce FTP')
	print('	SSH bruteforce 			:		ssh_bruteforce		| Bruteforce SSH')
	print('	Login panel			:		panelfinder		| Bruteforce dir to find login panels')
	print()

	print(bold(cyan('Network ')) + bold(purple('| ')) + bold(cyan(checkAvailable('Network'))))
	print('	IP locator			:		iplocator 		| Get IP location')
	print('	Reverse IP			:		reverse 		| IP domain lookup')
	print('	DNS records			:		dns_extractor 			| Extract DNS records')
	print('	Network Mapper			:		network_mapper		| Map network with NMap')
	print()

	print(bold(cyan('Information gathering ')) + bold(purple('| ')) + bold(cyan(checkAvailable('InformationGathering'))))
	print('	E-mail extraction		:		email_extractor		| Extract e-mail address')
	print('	Whois information		:		whois_extractor 	| Get whois information')
	print('	Metadata extraction		:		metadata_extractor 		| Extract metadata from files')
	print('	Spidering			:		spider 			| Extract links')
	print('	Subdomain discovery		:		subdomain 		| Discover subdomain')
	print()

#show author
def author():
	print()
	print(bold(lightred('About the author.')))
	print('Author: Sam Marx')
	print('Github: https://github.com/SamCEAP/')

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
