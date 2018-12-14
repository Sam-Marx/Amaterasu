#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

yes = {'yes', 'y', ''}
no = {'no', 'n'}

def mapper():
	with open('core/keys.json') as f:
		apiKeys = json.load(f)

	if 'Windows' in platform.system() or 'Darwin' in platform.system():
		target = input('Enter IP or URL: ')
		try:
			getPorts = requests.get('https://api.hackertarget.com/nmap/?q=' + target)
			print(getPorts.text)
		except Exception as e:
			print(bold(bad('Got an error: ' + str(e))))
		target = socket.gethostbyname(target)
		print()

		if apiKeys['APIs']['SHODAN_CHECK'] == True:
			checkShodan = input(que('Try to get with Shodan? [Y/n]\nUser: '))
			shodan_api = apiKeys['APIs']['SHODAN']

			if checkShodan.lower() in yes:
				try:
					api = shodan.Shodan(shodan_api)
					host = api.host(target)
					print()
					print(bold(good('IP: {}'.format(host['ip_str']))))
					print(bold(good('Operating System: {}'.format(host.get('os', 'n/a')))))
					for item in host['data']:
						print(bold(good('Port: {}'.format(item['port']))))
						print(bold(good('Banner: {}'.format(item['data']))))
					print()
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
		else:
			pass
	else:
		target = input('Enter IP or URL: ')
		port = input('Enter port range (default 80-443): ')
		target = socket.gethostbyname(target)

		nm = nmap.PortScanner()
		if port == '':
			port = '80-443'
		nm.scan(target, port)
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
			print()
			checkShodan = input(que('Try to get with Shodan (Y/n)? '))
			if checkShodan.lower() in yes:
				try:
					api = shodan.Shodan(shodan_api)
					host = api.host(target)
					print()
					print(bold(good('IP: {}'.format(host['ip_str']))))
					print(bold(good('Operating System: {}'.format(host.get('os', 'n/a')))))
					for item in host['data']:
						print(bold(good('Port: {}'.format(item['port']))))
						print(bold(good('Banner: {}'.format(item['data']))))
					print()
					print(bold(good('Organization: {}'.format(host.get('org', 'n/a')))))
				except Exception as e:
					print()
					print(bold(bad('Failed with Shodan: {}'.format(e))))
					pass
				except shodan.APIError as e:
					print(bold(bad('Error with API: {}'.format(e))))
		for proto in nm[host].all_protocols():
			print(bold(good('Protocol: ' + proto)))

			rport = nm[host][proto].keys()
			rport = list(rport)
			rport.sort()
			for p in rport:
				print(bold(good('Port: %s\tStatus: %s' % (p, nm[host][proto][p]['state']))))
