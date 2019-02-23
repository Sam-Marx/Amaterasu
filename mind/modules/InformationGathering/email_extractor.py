#coding: utf-8
#!/usr/bin/python3

from ruamel.yaml import YAML
from huepy import *
import tldextract
import requests
import pathlib
import json
import sys
import re
import os

def email_extractor_CONFIG():
	target = ''
	saveResults = ''
	HunterUse = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('email_extractor')) + ')' + '> ')
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
				elif user.split(' ')[1] == 'HunterUse' or user.split(' ')[1] == 'HUNTERUSE':
					HunterUse = user.split(' ')[2]
					if HunterUse == 'True' or HunterUse == 'False':
						print(bold(info('Use Hunter set: ' + HunterUse)))
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

					if HunterUse == 'True':
						HunterUse = 'True'
					else:
						HunterUse = 'False'

					sConfig = {'Target': target,
					'Save results': saveResults,
					'Use Hunter': HunterUse}
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
					'set saveResults [True/False]': 'save results to Results folder',
					'set HunterUse [True/False]': 'use hunter.io for email searching'}
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
				email_extractor(target, sf=saveResults, uh=HunterUse)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == '?' or user == 'help':
			sHelp = {'help | ?':'print this help message.',
			'show (config|options)':'show configuration or options',
			'set target': 'set target to scan',
			'set HunterUse [True/False]': 'use hunter.io for email searching',
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

def email_extractor(target, sf='', uh=''):
	config_file = open('core/config.yaml').read()
	yaml = YAML()
	config = yaml.load(config_file)
	api = config['API']

	ext = tldextract.extract(target)
	domain = ext.domain
	suffix = ext.suffix
	fullsite = domain + '.' + suffix

	allEmails = []
	allLinks = []
	functionalLinks = []

	if target.startswith('http://') or target.startswith('https://'):
		target = fullsite 

		a = requests.get('http://' + target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(a.text)
		for link in links:
			allLinks.append(link)
	else:
		target = 'http://' + target
		b = requests.get(target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(b.text)
		for link in links:
			allLinks.append(link)
	print()

	#Remove duplicates
	allLinks = sorted(set(allLinks))

	for link in allLinks:
		try:
			if link.startswith('//'):
				link = 'http:' + link
			if link.startswith('#'):
				link = target + '/' + link
			elif link.startswith('http'):
				link = link
			elif link.startswith(' '):
				link = link
			elif link.startswith('/'):
				link = target + link
			else:
				pass
			r = requests.get(link)
			if r.status_code == 200:
				print(bold(info('Trying to find e-mails in: ' + link + bold(green(' [')) + bold(yellow(str(r.status_code) + ' - successful')) + bold(green(']')))))
				functionalLinks.append(link)
			elif str(r.status_code).startswith('4') or r.status_code == 999:
				print(bold(info('Trying to find e-mails in: ' + link + bold(green(' [')) + bold(red(str(r.status_code) + ' - unsuccessful')) + bold(green(']')))))
			else:
				print(bold(info('Trying to find e-mails in: ' + link + bold(green(' [')) + bold(orange(str(r.status_code))) + bold(green(']')))))
			emails_searcher = re.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}")
			emails = emails_searcher.findall(r.text)

			for email in emails:
				allEmails.append(email)
		except KeyboardInterrupt:
			break
		except Exception as e:
			pass

	print()
	functionalLinks = sorted(set(functionalLinks))
	print(bold(info('Searched in ' + str(len(functionalLinks)) + ' directories.\n')))
	print(bold(info('Trying to find e-mails in PGP')))
	try:
		r = requests.get('https://pgp.mit.edu/pks/lookup?search={}&op=index'.format(domain + '.' + suffix))
		if r.status_code == 200:
			emails_searcher = re.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}")
			emails = emails_searcher.findall(r.text)

			if len(emails) is 0:
				print(bold(bad('Found 0 emails with hunter.io\n')))
			else:
				print(bold(good('Success: {}\n'.format(str(len(emails))))))

			for email in emails:
				allEmails.append(email)
			print(bold(good('Success.\n')))
		else:
			print(bold(bad('PGP failed.')))
	except KeyboardInterrupt:
		print(bold(bad('PGP failed.')))
		pass
	except Exception as e:
		print(bold(bad('PGP failed.')))
		print(bold(bad('Error: ' + str(e))))
	print()

	if uh == 'True':
		print(bold(info('Trying to find e-mails with Hunter.io')))
		hunter_api = api[4]['Hunter']
		try:
			hunter = requests.get('https://api.hunter.io/v2/domain-search?domain={}&api_key={}'.format(target, hunter_api))
			if hunter.status_code == 200:
				emails_searcher = re.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}")
				emails = emails_searcher.findall(hunter.text)

				for email in emails:
					allEmails.append(email)
				if len(emails) is 0:
					print(bold(bad('Found 0 emails with hunter.io\n')))
				else:
					print(bold(good('Success: {}\n'.format(str(len(emails))))))
			else:
				print(bold(bad('hunter.io failed.')))
		except KeyboardInterrupt:
			print(bold(bad('hunter.io failed.')))
			pass
		except Exception as e:
			print(bold(bad('hunter.io failed.')))
			print(bold(bad('Error: ' + str(e))))

	allEmails = sorted(set(allEmails))

	#Check for validity
	print(bold(info('Trying to check validity')))
	for email in allEmails:
		r = requests.get('https://api.trumail.io/v2/lookups/json?email=' + email)
		rjson = json.loads(r.text)
		try:
			if not rjson['deliverable']:
				print(bold(info('Not deliverable: '+ email + '.')))
				try:
					allEmails.remove(email)
				except ValueError as e:
					pass
			elif not rjson['hostExists']:
				print(bold(bad('Host of ' + email + ' do not exist.')))
				try:
					allEmails.remove(email)
				except ValueError as e:
					pass
			elif not rjson['validFormat']:
				print(bold(bad('Wrong email format: ' + email + '.')))
				try:
					allEmails.remove(email)
				except ValueError as e:
					pass
			else:
				print(bold(good('E-mail passed: ' + email)))
		except KeyError as e:
			print(bold(bad('Error: {}'.format(e))))
		except KeyboardInterrupt:
			pass
		except Exception as e:
			print(bold(bad('Error: ' + e)))

	print()
	
	for email in sorted(set(allEmails)):
		print(bold(green('E-mail found: ')) + email)

	if len(allEmails) is 0:
		print(bold(bad('Zero emails found.')))
	else:
		print()
		print(bold(good('Found: ' + str(len(allEmails)) + ' e-mails.')))
		if sf is not 'False' or '':
			if os.path.isdir('Results/' + domain + '.' + suffix) is False:
				p = pathlib.Path('Results/' + domain + '.' + suffix)
				p.mkdir(parents=True)
			else: pass
			try:
				f = open('Results/' + domain + '.' + suffix + '/' + domain + '.' + suffix + '_emails' + '.txt', 'w')
				for l in allEmails:
					f.write('%s\n' % l)
				f.close()
				print(bold(good('Saved.')))
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))

		else:
			pass
