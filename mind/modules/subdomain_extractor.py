#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

yes = {'yes', 'y', ''}
no = {'no', 'n'}

def censysEnum(target):
	with open('keys.json') as f:
		apiKeys = json.load(f)

	cert = censys.certificates.CensysCertificates(api_id = apiKeys['APIs']['CENSYS_UID'], api_secret = apiKeys['APIs']['CENSYS_SECRET'])
	f.close()

	fields = ['parsed.names']
	try:
		for c in cert.search('parsed.names: ' + '.' + target, fields = fields):
			print(c)
	except censys.base.CensysRateLimitExceededException:
		print(bad('Amaterasu exceeded your Censys account limits.'))
	except censys.base.CensysException as e:
		print(bad('Error with Censys: ' + e))
	except Exception as e:
		print(bad('Error: ' + e))

def subdomain():
	target = input('Enter domain: ')
	subdomains = []

	if target.startswith('http://') or target.startswith('https://'):
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix
		target = domain + '.' + suffix

		try:
			a = requests.get('https://crt.sh/?q=%.{}&output=json'.format(target), timeout=5)
			js = json.loads('[{}]'.format(a.text.replace('}{', '},{')))

			for (key, value) in enumerate(js):
				subdomains.append(value['name_value'])

		except Exception as e:
			print(bad('crt.sh not available: ' + str(e) + '\n'))
			censysCheck = input(que('Try to enumerate with Censys.io? [Y/n]\nUser: '))
			if censysCheck.startswith('y') or censysCheck in yes:
				censysEnum(target)
			else:
				pass
	else:
		try:
			a = requests.get('https://crt.sh/?q=%.{}&output=json'.format(target), timeout=5)
			js = json.loads('[{}]'.format(a.text.replace('}{', '},{')))

			for (key, value) in enumerate(js):
				subdomains.append(value['name_value'])

		except Exception as e:
			print(bad('crt.sh not available: ' + str(e) + '\n'))
			censysCheck = input(que('Try to enumerate with Censys.io? [Y/n]\nUser: '))
			if censysCheck.startswith('y') or censysCheck in yes:
				censysEnum(target)
			else:
				pass

	subdomains = sorted(set(subdomains))
	if subdomains == None:
		print(bad('Zero subdomains found.'))

	elif len(subdomains) > 0:
		for subdomain in subdomains:
			print(bold(green('Subdomain found: ')) + subdomain)
		print()
		print(bold(good('Found: ' + str(len(subdomains)))))
		save = input(que('Save them in .txt file? [Y/n]\nUser: '))
		if save in yes:
			f = open(target + '_subdomains' + '.txt', 'w')
			for s in subdomains:
				f.write('%s\n' % s)
			f.close()
			print(good('Saved.'))
		elif save.startswith('n') or save in no:
			pass
		else:
			print(bad('Enter yes or no.'))
