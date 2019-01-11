#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

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
					spider(target, sf='True')
				else:
					spider(target, sf='False')
			except Exception as e:
				print(bold(bad('Error: {}'.format(e))))
		elif user == 'back':
			break
		elif user == 'exit':
			print(bold(good('Thanks for using Amaterasu.')))
			sys.exit()

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
		r = requests.get('http://' + target + '/sitemap.xml')
		if r.status_code == 200:
			xml = r.text
			soup = BeautifulSoup(xml, 'lxml')
			sitemapTags = soup.find_all('sitemap')
			for sm in sitemapTags:
				xmlDict[sm.findNext('loc').text]
				if xmlDict.startswith('#'):
					xmlDict = target + xmlDict
					allLinks.append(xmlDict)
		else:
			pass
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

	if len(allLinks) is 0:
		print(bold(bad('Zero links found.')))
	else:
		print(bold(good('Found: ' + str(len(allLinks)))))
		if sf is not 'False' or '':
			try:
				f = open('Links/' + domain + '.' + suffix + '_links' + '.txt', 'w')
				for l in allLinks:
					f.write('%s\n' % l)
				f.close()
				print(bold(good('Saved.')))
			except IOError:
				print(bold(bad(bold(lightred('Links ')) + 'directory do not exist. Try to create manually.')))
		else:
			pass
