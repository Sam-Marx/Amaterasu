#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

yes = {'yes', 'y', ''}
no = {'no', 'n'}

def findPanel():
	try:
		target = input('Enter domain: ')
		file = input('Enter admin list: ')

		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix
		panelsFound = []
		print()
		if target.startswith('http://') or target.startswith('https://'):
			try:
				requests.get(target)
			except Exception as e:
				print(bad('Error: ' + str(e)))

			r = requests.get(target)
			f = open(file)
			for a in f.readlines():
				a = a.strip()
				r = requests.get(target + '/' + a)

				if r.status_code == 200 or r.status_code == 301:
					print(bold(good('Login panel found: ' + target + '/' + a)))
					panelsFound.append(target + '/' + a)

				elif r.status_code == 404:
					print(bold(bad('Login panel not found: ' + target + '/' + a)))

		else:
			target = 'http://' + target
			try:
				requests.get(target)
			except Exception as e:
				print(bad('Error: ' + str(e)))

			r = requests.get(target)
			f = open(file)
			for a in f.readlines():
				a = a.strip()
				r = requests.get(target + '/' + a)

				if r.status_code == 200 or r.status_code == 301:
					print(bold(good('Admin found: ' + target + '/' + a)))
					panelsFound.append(target + '/' + a)

				elif r.status_code == 404:
					print(bold(bad('Admin not found: ' + target + '/' + a)))
	except KeyboardInterrupt:
		print()
		for p in panelsFound:
			print(bold(good('Panel: ')) + p)
		print(bold(good('Found: ' + str(len(panelsFound)))))
