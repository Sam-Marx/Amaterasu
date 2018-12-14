#coding: utf-8
#!/usr/bin/python3

#MAIN
from core.main_imports import *

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
						show_help()
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
