#coding: utf-8
#!/usr/bin/python3

#MAIN
from core.banner import show_banners
from mind.modules.modules import *

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
	print(bold(yellow('[*]')) + " About me:					show system's info")
	
#show modules
def show_module():
	print()
	print(bold(cyan('Bruteforcing ')) + bold(purple('|')) + bold(cyan(' 5 modules')))
	print('	FTP bruteforce 			:		ftp_brute		| Bruteforce FTP')
	print('	SSH bruteforce 			:		ssh_brute		| Bruteforce SSH')
	print('	Login panel			:		panelfinder		| Bruteforce dir to find login panels')
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
	if platform.system() == 'Windows':
		print(bold(bad('Amaterasu cant be updated in Windows OS.')))
	else:
		os.system('git clone --depth=1 https://github.com/SamCEAP/Amaterasu.git')
		os.system('cd Amaterasu')
		os.system('python3 amaterasu.py')

def main():
	print_help()
	try:
		while True:
			user = input(bold(red('\nAMATERASU > '))).lower()
			if user.startswith('use'):
				try:
					if user.split(' ')[1] == 'mapper':
						try:
							mapper()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'whois':
						try:
							whois()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'email_ex':
						try:
							email_ex()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'metadata':
						try:
							metadata()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'reverse':
						try:
							reverse()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'iploc':
						try:
							iploc()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'spider':
						try:
							spider()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'subdomain':
						try:
							subdomain()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'social':
						try:
							social()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'dns_ex':
						try:
							dns_ex()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'ftp_brute':
						try:
							ftp_brute()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'panelfinder':
						try:
							findPanel()
						except KeyboardInterrupt:
							print()
							main()
					elif user.split(' ')[1] == 'ssh_brute':
						try:
							ssh_brute()
						except KeyboardInterrupt:
							print()
							main()
				except IndexError:
					show_module()
					print(bold(info('Select a module.')))

			elif user.startswith('show'):
				try:
					if user.split(' ')[1] == 'modules':
						show_module()
					elif user.split(' ')[1] == 'author':
						author()
					elif user.split(' ')[1] == 'banners':
						show_banners()
					elif user.split(' ')[1] == 'help':
						print_help()
					elif user.split(' ')[1] == 'bm':
						aboutme()
				except IndexError:
					print(bold(info('Select what to show.\n')))
					print(bold(info('Modules\t\tshow modules')))
					print(bold(info('Author\t\tshow author')))
					print(bold(info('Banners\t\tshow banners')))
					print(bold(info('About me\t\tshow bm')))
					print(bold(info('Help\t\tshow help')))

			elif user == 'exit':
				sys.exit()
			elif user == 'update':
				update()
			elif user == 'cls' or user == 'clear':
				clear()
			else:
				print(bad('Amaterasu could not understand.'))
	except KeyboardInterrupt:
		print()
		print(bad('"exit" to get out.'))
		print()
