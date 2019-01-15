#coding: utf-8
#!/usr/bin/python3

from huepy import *
import requests
import tldextract
import sys

def login_panel_CONFIG():
	target = ''
	file = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('panelfinder')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					print(bold(info('Target set: ' + target)))
				elif user.split(' ')[1] == 'file' or user.split(' ')[1] == 'FILE':
					file = user.split(' ')[2]
					print(bold(info('Admin wordlist set: ' + user)))
				else:
					print(bold(bad('Error: option do not exist.')))
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('admin wordlist\tset file FILE')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
				print(bold(info('admin wordlist\tset file FILE')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print(bold(info('Target:\t\t' + target)))
					print(bold(info('Admin wordlist:\t\t' + file)))
				elif user.split(' ')[1] == 'options':
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('admin wordlist\tset file FILE')))
				else:
					print(bold(bad('Error: option do not exist.')))
			except IndexError:
				print(bold(info('Select what to show.\n')))
				print(bold(info('Config\t\tshow config')))
				print(bold(info('Options\t\tshow options')))
		elif user.startswith('run'):
			try:
				findPanel(target, file)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def findPanel(target, file):
	try:
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix
		panelsFound = []
		print()
		if target.startswith('http://') or target.startswith('https://'):
			try:
				requests.get(target)
			except Exception as e:
				print(bad('Error: ' + str(e)))

			r = requests.get(target)
			f = open(file)
			for a in f.readlines():
				a = a.strip()
				r = requests.get(target + '/' + a)

				if r.status_code == 200 or r.status_code == 301:
					print(bold(good('Login panel found: ' + target + '/' + a)))
					panelsFound.append(target + '/' + a)

				elif r.status_code == 404:
					print(bold(bad('Login panel not found: ' + target + '/' + a)))

		else:
			target = 'http://' + target
			try:
				requests.get(target)
			except Exception as e:
				print(bad('Error: ' + str(e)))

			r = requests.get(target)
			f = open(file)
			for a in f.readlines():
				a = a.strip()
				r = requests.get(target + '/' + a)

				if r.status_code == 200 or r.status_code == 301:
					print(bold(good('Admin found: ' + target + '/' + a)))
					panelsFound.append(target + '/' + a)

				elif r.status_code == 404:
					print(bold(bad('Admin not found: ' + target + '/' + a)))
	except KeyboardInterrupt:
		print()
		for p in panelsFound:
			print(bold(good('Panel: ')) + p)
		print(bold(good('Found: ' + str(len(panelsFound)))))
