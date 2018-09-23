#coding: utf-8
#!/usr/bin/python3

#MAIN
from core.banner import banner
from mind.modules.modules import *

versao = '0.0.1'
from huepy import *
import platform
import os
import sys

#help
def print_help():
	print()
	print(bold(yellow('[*]')) + ' Help:					print this help message.')
	print(bold(yellow('[*]')) + ' Exit:					leave the program.')
	print(bold(yellow('[*]')) + ' Use:					use module.')
	print(bold(yellow('[*]')) + ' Show modules:				show modules.')
	print(bold(yellow('[*]')) + ' Clear:					clear the terminal.')
	print(bold(yellow('[*]')) + ' Update:					update the framework.')
	print(bold(yellow('[*]')) + ' Author:					about Amaterasu framework.')

#show modules
def show_module():
	print()
	print(bold(cyan('Bruteforcing ')) + bold(purple('|')) + bold(cyan(' 5 modules')))
	print('	WordPress bruteforce		:		wp_brute		| Bruteforce WP Panel')
	print('	Joomla bruteforce		:		jm_brute		| Bruteforce Joomla Panel')
	print('	Drupal bruteforce		:		dp_brute		| Bruteforce Drupal Panel')
	print('	FTP bruteforce 			:		ftp_brute		| Bruteforce FTP')
	print('	SSH bruteforce 			:		ssh_brute		| Bruteforce SSH')
	print()

	print(bold(cyan('Network ')) + bold(purple('|')) + bold(cyan(' 3 modules')))
	print('	IP locator			:		iploc 			| Get IP location')
	print('	Reverse IP			:		reverse 		| IP domain lookup')
	print('	NMap				:		nmap 			| Map network with nmap')
	print()

	print(bold(cyan('information Gathering ')) + bold(purple('|')) + bold(cyan(' 6 modules')))
	print('	E-mail extraction		:		email_ex		| Extract e-mail address')
	print('	Whois information		:		whois 			| Get whois information')
	print('	Metadata extraction		:		metadata 		| Extract metadata from files')
	print('	Social				:		social 			| Extract social informations')
	print('	Spidering			:		spider 			| Extract links')
	print('	Subdomain discovery		:		subdomain 		| Discover subdomain')
	print()

	print(bold(cyan('Exploitation ')) + bold(purple('|')) + bold(cyan(' 2 modules')))
	print('	CVE-2012-3152			:		c_2012_3152		| Oracle Local File Inclusion (LFI) exploit')
	print('	CVE-2014-6271			:		c_2014_6271		| ShellShock exploit')
	print()

	print(bold(cyan('Post exploitation ')) + bold(purple('|')) + bold(cyan(' 3 modules')))
	print('	MSFVenom backdoor		:		msf_backdoor 		| Create a backdoor with MSFVenom')
	print('	Generate backdoor		:		gen_backdoor 		| Generate a FUD backdoor')
	print('	Data harvesting			:		data_harvest		| Harvest data of the system with backdoor')
	print()

	print(bold(cyan('Extras ')) + bold(purple('|')) + bold(cyan(' 2 modules')))
	print('	Ransomware			:		ransomw 		| Create a ransomware')
	print('	Reverse shell 			:		py_reverse		| Create a python reverse shell')

#author
def author():
	print()
	print(bold(lightred('About the author.')))
	print('Author: Sam Marx')
	print('Facebook: facebook.com/s4mmarx')
	print('Github: https://github.com/PyOtho/')

#clear
def clear():
	if platform.system() == 'Windows':
		os.system('cls')
	else:
		os.system('clear')

#update
def update():
	pass

#use

#main
def main():
	print_help()

	try:
		while True:
			user = input(bold(red('\nAMATERASU > '))).lower()

			if user == 'help':
				print_help()
			elif user == 'clear':
				clear()
			elif user == 'cls':
				print(que('Do you mean "clear"?'))
			elif user == 'banner':
				banner(versao)
			elif user == 'exit':
				sys.exit()
			elif user == 'show':
				print(bad('Show what?'))
			elif user == 'show modules':
				clear()
				show_module()
			elif user == 'baner':
				print(que('Do you mean "banner"?'))
			elif user == 'author':
				author()
			elif user == 'use':
				print('Select a module.')
				show_module()
			elif user == 'use iploc':
				try:
					iploc()
				except KeyboardInterrupt:
					print()
					main()

			elif user == 'use reverse':
				try:
					reverse()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use spider':
				try:
					spider()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use whois':
				try:
					whois()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'update':
				update()
			else:
				print(bad('Amaterasu could not understand.'))
	except KeyboardInterrupt:
		print()
		print(bad('"Exit" to get out.'))
		print()
