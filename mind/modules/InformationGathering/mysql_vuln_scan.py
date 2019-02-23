#coding: utf-8
#!/usr/bin/python3

from googlesearch import search
from huepy import *
import tldextract
import requests
import sys

def mysql_vuln_scanner_CONFIG():
	target = ''
	useGoogle = ''
	dorklist = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('mysql_vuln_scanner')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					print(bold(info('Target set: ' + target)))
				elif user.split(' ')[1] == 'useGoogle' or user.split(' ')[1] == 'USEGOOGLE':
					useGoogle = user.split(' ')[2]
					if useGoogle == 'True' or useGoogle == 'False':
						print(bold(info('set Google set: ' + useGoogle)))
					else:
						print(bold(bad('Error: only True or False.')))
				elif user.split(' ')[1] == 'dorklist' or user.split(' ')[1] == 'DORKLIST':
					dorklist = user.split(' ')[2]
					print(bold(info('Dork list set: ' + dorklist)))
				else:
					print(bold(bad('Error: option do not exist.')))
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('set Google\tset useGoogle True/False (default: False)')))
					print(bold(info('set dorklist\tset dorklist DORKLIST')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
				print(bold(info('set Google\tset useGoogle True/False (default: False)')))
				print(bold(info('set dorklist\tset dorklist DORKLIST')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print()
					if useGoogle == 'True':
						useGoogle = 'True'
					else:
						useGoogle = 'False'
					sConfig = {'Target': target,
					'set Google': useGoogle,
					'Dork list': dorklist}
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
					'set useGoogle [True/False]': 'use Google to find websites',
					'set dorklist [DORKLIST]': 'Dorklist'}
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
				if useGoogle == 'True':
					mysql_vuln_scanner(target, ug='True', dorklist=dorklist)
				else:
					mysql_vuln_scanner(target, ug='False')
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'set target to scan',
			'set useGoogle': 'use Google to find vulnerable websites',
			'set dorklist': 'set dorklist to be used for Google scanning',
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
		else:
			print(bold(bad('Command not found.')))

def mysql_vuln_scanner(target = '', ug = '', dorklist = ''):
	checkVulns = []
	vulns = []
	print()

	try:
		if target.endswith('.txt'):
			filelist = open(target, 'r')

			for d in filelist.readlines():
				target = d.strip()

				if target.startswith('http://') or target.startswith('https://'):
					checkVulns.append(target)
				else:
					checkVulns.append('http://' + target)

		elif target.startswith('http://') or target.startswith('https://'):
			checkVulns.append(target)
		else:
			checkVulns.append('http://' + target)

		if ug is 'True':
			dorkList = open(dorklist, 'r')
			for d in dorkList.readlines():
				dork = d.strip()

				try:
					for url in search(dork, stop = 100, start = 0):
						checkVulns.append(url)
				except Exception as e:
					print(bold(bad('Error: {}'.format(e))))

		#print()
		for s in checkVulns:
			try:
				r = requests.get(s + "'")
				if 'error' in r.text and 'syntax' in r.text or 'MySQL' in r.text:
					print(bold(good(s + ' is vulnerable.')))
					vulns.append(s)
				else:
					print(bold(bad(s + ' is not vulnerable.')))
			except Exception:
				pass

		print()
		for s in vulns:
			print(bold(good('Vulnerable: ' + s)))
		print(bold(good('Targets vulnerables: ' + str(len(vulns)))))
	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))
		

	
