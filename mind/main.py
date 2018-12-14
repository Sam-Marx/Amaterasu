#coding: utf-8
#!/usr/bin/python3

#MAIN
from core.main_imports import *
from core.main_update import *
from core.main_clear import *

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
					if user.split(' ')[1] == 'shodan_api':
						with open('core/keys.json', 'r+') as f:
							apiKeys = json.load(f)
							tmp = apiKeys
							apiKeys['APIs']['SHODAN'] = user.split(' ')[2]
							apiKeys['APIs']['SHODAN_CHECK'] = "True"
							f.seek(0)
							json.dump(apiKeys, f, indent=4)
							print(bold(info('Shodan API\t' + user.split(' ')[2])))
						f.close()

					elif user.split(' ')[1] == 'censys_uid':
						with open('core/keys.json', 'r+') as f:
							apiKeys = json.load(f)
							tmp = apiKeys
							apiKeys['APIs']['CENSYS_UID'] = user.split(' ')[2]
							apiKeys['APIs']['CENSYS_UID_CHECK'] = "True"
							f.seek(0)
							json.dump(apiKeys, f, indent=4)
							print(bold(info('Censys UID\t\t' + user.split(' ')[2])))
							f.close()
					elif user.split(' ')[1] == 'censys_secret':
						with open('core/keys.json', 'r+') as f:
							apiKeys = json.load(f)
							tmp = apiKeys
							apiKeys['APIs']['CENSYS_SECRET'] = user.split(' ')[2]
							apiKeys['APIs']['CENSYS_SECRET_CHECK'] = "True"
							f.seek(0)
							json.dump(apiKeys, f, indent=4)
							print(bold(info('Censys SECRET\t' + user.split(' ')[2])))
							f.close()

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
						show_banners(versao)
					elif user.split(' ')[1] == 'help':
						show_help()
					elif user.split(' ')[1] == 'bm':
						aboutme()
					elif user.split(' ')[1] == 'keys':
						show_keys()
				except IndexError:
					print(bold(info('Select what to show.\n')))
					print(bold(info('Modules\t\tshow modules')))
					print(bold(info('Author\t\tshow author')))
					print(bold(info('Banners\t\tshow banners')))
					print(bold(info('About me\t\tshow bm')))
					print(bold(info('Help\t\tshow help')))

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
