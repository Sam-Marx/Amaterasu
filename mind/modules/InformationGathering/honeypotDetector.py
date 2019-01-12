#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

def honeypot_detector_CONFIG():
	target = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('honeypot_detector')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
					target = user.split(' ')[2]
					print(bold(info('Target set: ' + target)))
				else:
					print(bold(bad('Error: option do not exist.')))
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
			except IndexError:
				print(bold(info('Select what to set.\n')))
				print(bold(info('target\tset target TARGET')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					print(bold(info('Target:\t\t' + target)))
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
				honeypot_detector(target)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def honeypot_detector(target):
	config_file = open('core/config.yaml').read()
	yaml = YAML()
	config = yaml.load(config_file)
	api = config['API']
	shodan_api = api[0]['Shodan']

	try:
		r = requests.get('https://api.shodan.io/labs/honeyscore/' + target + '?key=' + shodan_api)
		r = r.text
	except Exception as e:
		print(bold(bad('Error: {}'.format(e))))

	if r:
		if float(r) < 0.5:
			print(bold(good('Honeypot probability: ' + r)))
		else:
			print(bold(bad('Honeypot probability: ' + r)))
