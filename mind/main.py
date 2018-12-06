#coding: utf-8
#!/usr/bin/python3

#MAIN
from core.banner import show_banners
from mind.modules.modules import *

versao = '1.0.4'
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
	print('	FTP bruteforce 			:		ftp_brute		| Bruteforce FTP')
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
	print('	Spidering			:		spider 			| Extract links')
	print('	Subdomain discovery		:		subdomain 		| Discover subdomain')
	print()

#author
def author():
	print()
	print(bold(lightred('About the author.')))
	print('Author: Sam Marx')
	print('Github: https://github.com/SamCEAP/')

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
				clear()
			elif user == 'banner':
				show_banners(versao)
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
			elif user == 'use mapper':
				try:
					mapper()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use iploc':
				try:
					iploc()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use metadata':
				try:
					metadata()
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
			elif user == 'use email_ex':
				try:
					email_ex()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use email_ex':
				try:
					email_ex()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use subdomain':
				try:
					subdomain()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use social':
				try:
					social()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use keylog':
				try:
					keylog()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use dns_ex':
				try:
					dns_ex()
				except KeyboardInterrupt:
					print()
					main()
			elif user == 'use ftp_brute':
				try:
					ftp_brute()
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
