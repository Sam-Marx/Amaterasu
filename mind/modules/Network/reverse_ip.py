#coding: utf-8
#!/usr/bin/python3

from huepy import *
import requests
import os
import pathlib
import sys
import tldextract

def reverse_ip_CONFIG():
	target = ''
	saveResults = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('reverse_ip')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					print(bold(info('Target set: ' + target)))
				elif user.split(' ')[1] == 'saveResults' or user.split(' ')[1] == 'SAVERESULTS':
					saveResults = user.split(' ')[2]
					if saveResults == 'True' or saveResults == 'False':
						print(bold(info('Save results set: ' + saveResults)))
					else:
						print(bold(bad('Error: only True or False.')))
				else:
					print(bold(bad('Error: option do not exist.')))
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('save results\tset saveResults True/False (default: False)')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
				print(bold(info('save results\tset saveResults True/False (default: False)')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print()
					if saveResults == 'True':
						saveResults = 'True'
					else:
						saveResults = 'False'
					sConfig = {'Target': target,
					'Save results': saveResults}
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
					'set saveResults [True/False]': 'save results to Results folder'}
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
				if saveResults == 'True':
					reverse_ip(target, sf='True')
				else:
					reverse_ip(target, sf='False')
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'set target to scan',
			'set saveResults': 'save all results in Results folder',
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

def reverse_ip(target, sf=''):
	if target.startswith('http://') or target.startswith('https://'):
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix

		target = domain + '.' + suffix
	else:
		pass

	url = 'http://api.hackertarget.com/reverseiplookup/?q='
	r = requests.get(url + target)
	n = r.text

	print()
	for l in n.splitlines():
		print(bold(green('Domain found: ')) + l)
	print()

	if len(n) is 0:
		print(bold(bad('Zero domains found.')))
	else:
		print()
		print(bold(good('Found: ' + str(len(n)) + ' domains.')))
		if sf is not 'False' or '':
			if os.path.isdir('Results/' + target) is False:
				p = pathlib.Path('Results/' + target)
				p.mkdir(parents=True)
			else: pass
			try:
				f = open('Results/' + target + '/' + target + '_reverseip_domains' + '.txt', 'w')
				for l in n.splitlines():
					f.write('%s\n' % l)
				f.close()
				print(bold(good('Saved.')))
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))

		else:
			pass
