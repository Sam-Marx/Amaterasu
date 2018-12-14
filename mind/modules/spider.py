#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

yes = {'yes', 'y', ''}
no = {'no', 'n'}

def spider():
	allLinks = []
	target = input('Enter URL: ')

	print()
	if target.startswith('http://') or target.startswith('https://'):
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix
		target = 'http://' + domain + '.' + suffix

		r = requests.get(target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(r.text)
		for link in links:
			print(bold(green('Link found: ')) + link)
			allLinks.append(link)
	else:
		r = requests.get('http://' + target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(r.text)
		for link in links:
			print(bold(green('Link found: ')) + link)
			allLinks.append(link)
	print()

	if len(allLinks) is 0:
		print(bad('Zero links found.'))
	else:
		print(bold(good('Found: ' + str(len(allLinks)))))
		save = input(que('Save them in .txt file? [Y/n]\nUser: '))
		if save in yes:
			f = open(domain + '.' + suffix + '_links' + '.txt', 'w')
			for l in allLinks:
				f.write('%s\n' % l)
			f.close()
			print(good('Saved.'))
		elif save in no:
			pass
		else:
			print(bad('Enter yes or no.'))
