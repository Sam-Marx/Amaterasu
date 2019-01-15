#coding: utf-8
#!/usr/bin/python3

from huepy import *
import requests
import sys

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
				if saveResults == 'True':
					reverse_ip(target, sf='True')
				else:
					reverse_ip(target, sf='False')
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def reverse_ip(target, sf=''):
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
		print(bold(good('Found: ' + str(len(n.splitlines())))))
		if sf is not 'False' or '':
			try:
				f = open('Results/' + target + '_reverseip_domains' + '.txt', 'w')
				for l in n.splitlines():
					f.write('%s\n' % l)
				f.close()
				print(bold(good('Saved.')))
			except IOError:
				print(bold(bad(bold(lightred('Results ')) + 'directory do not exist. Try to create manually.')))
		else:
			pass
