#coding: utf-8
#!/usr/bin/python3

from huepy import *
import tldextract
import requests
import sys
import re

def spider_CONFIG():
	target = ''
	saveResults = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('spider')) + ')' + '> ')
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
					print(bold('CONFIG\t\t\tDESCRIPTION'))
					print(bold('------\t\t\t-----------'))
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
					'set saveResults': 'Save results [True / False]'}
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
					spider(target, sf='True')
				else:
					spider(target, sf='False')
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'set target [TARGET]',
			'set saveResults': 'set saveResults [True/False]',
			'run':'execute module'}
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

def spider(target, sf=''):
	allLinks = []

	ext = tldextract.extract(target)
	domain = ext.domain
	suffix = ext.suffix

	print()
	if target.startswith('http://') or target.startswith('https://'):
		target = 'http://' + domain + '.' + suffix

		r = requests.get(target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(r.text)
		for link in links:
			if link.startswith('/'):
				link = target + link
			print(bold(green('Link found: ')) + link)
			allLinks.append(link)
	else:
		r = requests.get('http://' + target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(r.text)
		for link in links:
			if link.startswith('/'):
				link = target + link
			print(bold(green('Link found: ')) + link)
			allLinks.append(link)

	print()
	allLinks = sorted(set(allLinks))

	if len(allLinks) is 0:
		print(bold(bad('Zero links found.')))
	else:
		print()
		print(bold(good('Found: ' + str(len(allLinks)))))
		if sf is not 'False' or '':
			try:
				f = open('Results/' + domain + '.' + suffix + '_links' + '.txt', 'w')
				for l in allLinks:
					f.write('%s\n' % l)
				f.close()
				print(bold(good('Saved.')))
			except IOError:
				print(bold(bad(bold(lightred('Results ')) + 'directory do not exist. Try to create manually.')))
		else:
			pass
