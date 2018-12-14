#coding: utf-8
#!/usr/bin/python3

#MAIN
from core.main_imports import *
from core.main_update import *
from core.main_clear import *
from core.main_show import *

config = configparser.RawConfigParser()
config.optionxform = str

def main():
	show_help()
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

			elif user.startswith('set'):
				try:
					if user.split(' ')[1] == 'shodan':
						config.read_string('core/config.ini')
						config['API']['Shodan'] = user.split(' ')[2]
						print(bold(info('Shodan API\t' + user.split(' ')[2])))
						with open('core/config.ini', 'w') as cf:
							config.write(cf)

					elif user.split(' ')[1] == 'censys_uid':
						config.read_string('core/config.ini')
						config['API']['Censys UID'] = user.split(' ')[2]
						print(bold(info('Censys UID\t' + user.split(' ')[2])))
						with open('core/config.ini', 'w') as cf:
							config.write(cf)

					elif user.split(' ')[1] == 'censys_secret':
						config.read_string('core/config.ini')
						config['API']['Censys SECRET'] = user.split(' ')[2]
						print(bold(info('Censys SECRET\t' + user.split(' ')[2])))
						with open('core/config.ini', 'w') as cf:
							config.write(cf)
				except IndexError:
					print(bold(info('Select what to set\n')))
					print(bold(info('API KEY\t\tset (shodan|censys_uid|censys_secret) API_KEY')))
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
					elif user.split(' ')[1] == 'banners':
						show_banners()
					elif user.split(' ')[1] == 'help':
						show_help()
					elif user.split(' ')[1] == 'bm':
						aboutme()
					elif user.split(' ')[1] == 'apis':
						show_API()
				except IndexError:
					print(bold(info('Select what to show.\n')))
					print(bold(info('Modules\t\tshow modules')))
					print(bold(info('Author\t\tshow author')))
					print(bold(info('Banners\t\tshow banners')))
					print(bold(info('About me\t\tshow bm')))
					print(bold(info('Help\t\tshow help')))
					print(bold(info('API\t\t\tshow apis')))

			elif user == 'exit':
				print(bold(good('Thanks for using Amaterasu.')))
				sys.exit()
			elif user == 'cls' or user == 'clear':
				clear()
			elif user == 'update':
				update()
			elif user == '?':
				show_help()
			else:
				print(bad('Amaterasu could not understand.'))
	except KeyboardInterrupt:
		print()
		print(bad('"exit" to get out.'))
		print()
