#coding: utf-8
#!/usr/bin/python3

from huepy import *
import tldextract
import requests
import pathlib
import sys
import re

def email_extractor_CONFIG():
	target = ''
	saveResults = ''

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
					print(bold(info('Target:\t\t' + target)))
					if saveResults == 'True':
						saveResults = 'True'
						print(bold(info('Save results:\t' + saveResults)))
					else:
						saveResults = 'False'
						print(bold(info('Save results:\t' + saveResults)))
				elif user.split(' ')[1] == 'options':
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
				else:
					print(bold(bad('Error: option do not exist.')))
			except IndexError:
				print(bold(info('Select what to show.\n')))
				print(bold(info('Config\t\tshow config')))
				print(bold(info('Options\t\tshow options')))
		elif user.startswith('run'):
			try:
				if saveResults is not 'False':
					email_extractor(target, sf='True')
				else:
					email_extractor(target, sf='False')
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def email_extractor(target, sf=''):
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
		b = requests.get('http://' + target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(b.text)
		for link in links:
			allLinks.append(link)
	print()

	allLinks = sorted(set(allLinks))

	for link in allLinks:
		try:
			if link.startswith('/'):
				link = target + link
			if link.startswith('#'):
				pass
			r = requests.get(link)
			if r.status_code == 200:
				print(bold(info('Trying to find e-mails in: ' + link + bold(green(' [')) + bold(yellow(r.status_code)) + bold(green(']')))))
				functionalLinks.append(link)
			elif r.status_code == 404:
				print(bold(info('Trying to find e-mails in: ' + link + bold(green(' [')) + bold(red(r.status_code)) + bold(green(']')))))
			else:
				print(bold(info('Trying to find e-mails in: ' + link + bold(green(' [')) + bold(orange(r.status_code)) + bold(green(']')))))
			emails_searcher = re.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}")
			emails = emails_searcher.findall(r.text)

			for email in emails:
				allEmails.append(email)
		except KeyboardInterrupt:
			break
		except:
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

			for email in emails:
				allEmails.append(email)
		else:
			print(bold(bad('PGP failed.')))
	except Exception as e:
		print(bold(bad('Error: ' + str(e))))
	print()

	allEmails = sorted(set(allEmails))

	for mail in allEmails:
		print(bold(green('E-mail found: ')) + mail)

	if len(allEmails) is 0:
		print(bold(bad('Zero emails found.')))
	else:
		print()
		print(bold(good('Found: ' + str(len(allEmails)))))
		if sf is not 'False' or '':
			try:
				f = open('Results/' + domain + '.' + suffix + '_emails' + '.txt', 'w')
				for l in allEmails:
					f.write('%s\n' % l)
				f.close()
				print(bold(good('Saved.')))
			except IOError:
				print(bold(bad(bold(lightred('Results ')) + 'directory do not exist. Try to create manually.')))
		else:
			pass
