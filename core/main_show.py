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
	print(bold(info(" About me:					show system's info.")))

#show modules
def show_module():
	print()
	print(bold(cyan('Bruteforcing ')) + bold(purple('|')) + bold(cyan(' 3 modules')))
	print('	FTP bruteforce 			:		ftp_brute		| Bruteforce FTP')
	print('	SSH bruteforce 			:		ssh_brute		| Bruteforce SSH')
	print('	Login panel			:		panelfinder		| Bruteforce dir to find login panels')
	print()

	print(bold(cyan('Network ')) + bold(purple('|')) + bold(cyan(' 4 modules')))
	print('	IP locator			:		iploc 			| Get IP location')
	print('	Reverse IP			:		reverse 		| IP domain lookup')
	print('	DNS records			:		dns_ex 			| Extract DNS records')
	print('	Network Mapper			:		mapper			| Map network with NMap')
	print()

	print(bold(cyan('information Gathering ')) + bold(purple('|')) + bold(cyan(' 5 modules')))
	print('	E-mail extraction		:		email_ex		| Extract e-mail address')
	print('	Whois information		:		whois 			| Get whois information')
	print('	Metadata extraction		:		metadata 		| Extract metadata from files')
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
	config = configparser.ConfigParser()
	config.read('core/config.ini')
	print(bold(info('Shodan API:    {}'.format(config['API']['shodan']))))
	print(bold(info('Censys UID:    {}'.format(config['API']['censys uid']))))
	print(bold(info('Censys SECRET: {}'.format(config['API']['censys secret']))))
