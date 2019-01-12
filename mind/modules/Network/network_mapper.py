#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

def network_mapper_CONFIG():
	target = ''
	ports = '80-443'
	ShodanUse = ''

	while True:
		user = input(bold(red('\nAMATERASU ')) + '(' + bold(lightcyan('network_mapper')) + ')' + '> ')
		if user.startswith('set'):
			try:
				if 'Windows' in platform.system():
					if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
						target = user.split(' ')[2]
						print(bold(info('Target set: ' + target)))
					elif user.split(' ')[1] == 'ShodanUse' or user.split(' ')[1] == 'SHODANUSE':
						if user.split(' ')[2] == 'True':
							ShodanUse = 'True'
							print(bold(info('Use Shodan set: ' + ShodanUse)))
						elif user.split(' ')[2] == 'False':
							ShodanUse = 'False'
							print(bold(info('Use Shodan set: ' + ShodanUse)))
						else:
							print(bold(bad('Error: only True or False.')))
					else:
						print(bold(bad('Error: option do not exist.')))
						print(bold(info('Select what to set.\n')))
						print(bold(info('target\tset target TARGET')))
						print(bold(info('use shodan\tset ShodanUse True/False')))
				else:
					if user.split(' ')[1] == 'target' or user.split(' ')[1] == 'TARGET':
						target = user.split(' ')[2]
						print(bold(info('Target set: ' + target)))
					elif user.split(' ')[1] == 'ports' or user.split(' ')[1] == 'PORTS':
						ports = user.split(' ')[2]
						print(bold(info('Ports set: ' + ports)))
					elif user.split(' ')[1] == 'ShodanUse' or user.split(' ')[1] == 'SHODANUSE':
						if user.split(' ')[2] == 'True':
							ShodanUse = 'True'
						elif user.split(' ')[2] == 'False':
							ShodanUse = 'False'
						else:
							print(bold(bad('Error: only True or False.')))
					else:
						print(bold(bad('Error: option do not exist.')))
						print(bold(info('Select what to set.\n')))
						print(bold(info('target\tset target TARGET')))
						print(bold(info('ports\tset ports PORT-PORT (default: 80-443)')))
						print(bold(info('use shodan\tset ShodanUse True/False')))
			except IndexError:
				if 'Windows' in platform.system():
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('use shodan\tset ShodanUse True/False')))
				else:
					print(bold(info('Select what to set.\n')))
					print(bold(info('target\tset target TARGET')))
					print(bold(info('ports\tset ports PORT-PORT (default: 80-443)')))
					print(bold(info('use shodan\tset ShodanUse True/False')))
		elif user.startswith('show'):
			try:
				if user.split(' ')[1] == 'config':
					if 'Windows' in platform.system():
						print(bold(info('Target:\t\t' + target)))
						print(bold(info('Use Shodan:\t\t' + ShodanUse)))
					else:
						print(bold(info('Target:\t\t' + target)))
						print(bold(info('Ports:\t\t' + ports)))
						print(bold(info('Use Shodan:\t\t' + ShodanUse)))
				elif user.split(' ')[1] == 'options':
					if 'Windows' in platform.system():
						print(bold(info('Select what to set.\n')))
						print(bold(info('target\tset target TARGET')))
						print(bold(info('use shodan\tset ShodanUse True/False')))
					else:
						print(bold(info('Select what to set.\n')))
						print(bold(info('target\tset target TARGET')))
						print(bold(info('ports\tset ports PORT-PORT (default: 80-443)')))
						print(bold(info('use shodan\tset ShodanUse True/False')))
				else:
					print(bold(bad('Error: option do not exist.')))
			except IndexError:
				print(bold(info('Select what to show.\n')))
				print(bold(info('Config\t\tshow config')))
				print(bold(info('Options\t\tshow options')))
		elif user.startswith('run'):
			try:
				if 'Windows' in platform.system():
					network_mapper(target, ShodanUse)
				else:
					networkmapper(target, ports, ShodanUse)
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

def network_mapper(target, ShodanUse):
	config_file = open('core/config.yaml').read()
	yaml = YAML()
	config = yaml.load(config_file)
	api = config['API']

	try:
		getPorts = requests.get('https://api.hackertarget.com/nmap/?q=' + target)
		print(getPorts.text)
	except Exception as e:
		print(bold(bad('Got an error: ' + str(e))))
	target = socket.gethostbyname(target)
	print()

	if ShodanUse == 'True':
		shodan_api = api[0]['Shodan']
		try:
			api = shodan.Shodan(shodan_api)
			host = api.host(target)
			print()
			print(bold(good('IP: {}'.format(host['ip_str']))))
			print(bold(good('Operating System: {}'.format(host.get('os', 'n/a')))))
			for item in host['data']:
				print(bold(good('Port: {}'.format(item['port']))))
				print(bold(good('Banner: {}'.format(item['data']))))
			print(bold(good('Organization: {}'.format(host.get('org', 'n/a')))))
		except Exception as e:
			print()
			print(bold(bad('Failed with Shodan: {}'.format(e))))
			pass
		except shodan.APIError as e:
			print(bold(bad('Error with API: {}'.format(e))))
			pass

def networkmapper(target, ports, ShodanUse):
	target = socket.gethostbyname(target)
	nm = nmap.PortScanner()
	if ports == '80-443':
		pass
	else:
		ports = ports

	nm.scan(target, ports)
	print(nm.command_line())
	for host in nm.all_hosts():
		print()
		print(bold(good('Host: %s (%s)' % (host, nm[host].hostname()))))
		print(bold(good('State: %s' % nm[host].state())))
	nm.scan(target, arguments='-O')
	if 'osclass' in nm[target]:
		for osclass in nm[target]['osclass']:
			print(bold(good('OS type: %s' % osclass['type'])))
			print(bold(good('OS vendor: %s' % osclass['vendor'])))
			print(bold(good('OS family: %s' % osclass['osfamily'])))
			print(bold(good('OS gen: %s' % osclass['osgen'])))
			print(bold(good('OS accuracy: %s' % osclass['accuracy'])))
	else:
		pass
	if ShodanUse == 'True':
		shodan_api = api[0]['Shodan']
		try:
			api = shodan.Shodan(shodan_api)
			host = api.host(target)
			print()
			print(bold(good('IP: {}'.format(host['ip_str']))))
			print(bold(good('Operating System: {}'.format(host.get('os', 'n/a')))))
			for item in host['data']:
				print(bold(good('Port: {}'.format(item['port']))))
				print(bold(good('Banner: {}'.format(item['data']))))
			print(bold(good('Organization: {}'.format(host.get('org', 'n/a')))))
		except Exception as e:
			print()
			print(bold(bad('Failed with Shodan: {}'.format(e))))
			pass
		except shodan.APIError as e:
			print(bold(bad('Error with API: {}'.format(e))))
			pass
	else:
		pass

	for proto in nm[host].all_protocols():
		print(bold(good('Protocol: ' + proto)))

		rport = nm[host][proto].keys()
		rport = list(rport)
		rport.sort()
		for p in rport:
			print(bold(good('Port: %s\tStatus: %s' % (p, nm[host][proto][p]['state']))))
