#coding: utf-8
#!/usr/bin/python3
#functions show

from huepy import *
import os
import os.path

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
	print(bold(info('Modules available: {}'.format(len([name for name in os.listdir(DIR) if os.path.isfile(name)])))))
	print(bold(cyan('Bruteforcing ')) + bold(purple('|')) + bold(cyan(' 5 modules')))
	print('	WordPress bruteforce		:		wp_brute		| Bruteforce WP Panel')
	print('	Joomla bruteforce		:		jm_brute		| Bruteforce Joomla Panel')
	print('	Drupal bruteforce		:		dp_brute		| Bruteforce Drupal Panel')
	print('	FTP bruteforce 			:		ftp_brute		| Bruteforce FTP')
	print('	SSH bruteforce 			:		ssh_brute		| Bruteforce SSH')
	print('	Admin panel finder		:		adminfinder		| Bruteforce directories to find admin panel')
	print()

	print(bold(cyan('Network ')) + bold(purple('|')) + bold(cyan(' 3 modules')))
	print('	IP locator			:		iploc 			| Get IP location')
	print('	Reverse IP			:		reverse 		| IP domain lookup')
	print('	DNS records			:		dns_ex 			| Extract DNS records')
	print('	Network Mapper			:		mapper			| Map network with NMap')
	print()

	print(bold(cyan('information Gathering ')) + bold(purple('|')) + bold(cyan(' 6 modules')))
	print('	E-mail extraction		:		email_ex		| Extract e-mail address')
	print('	Whois information		:		whois 			| Get whois information')
	print('	Metadata extraction		:		metadata 		| Extract metadata from files')
	print('	Social				:		social 			| Extract web social profiles')
	print('	Spidering			:		spider 			| Extract links')
	print('	Subdomain discovery		:		subdomain 		| Discover subdomain')
	print()

#show author
def author():
	print()
	print(bold(lightred('About the author.')))
	print('Author: Sam Marx')
	print('Github: https://github.com/SamCEAP/')
