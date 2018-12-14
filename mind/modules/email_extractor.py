#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

yes = {'yes', 'y', ''}
no = {'no', 'n'}

def email_ex():
	target = input('Enter URL: ')

	ext = tldextract.extract(target)
	domain = ext.domain
	suffix = ext.suffix
	fullsite = domain + '.' + suffix

	allEmails = []
	allLinks = []
	if target.startswith('http://') or target.startswith('https://'):
		target = 'http://' + domain + '.' + suffix

		a = requests.get(target)
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

	for link in allLinks:
		try:
			r = requests.get(link)
			emails_searcher = re.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}")
			emails = emails_searcher.findall(r.text)

			for email in emails:
				allEmails.append(email)
		except:
			pass

	allEmails = sorted(set(allEmails))

	for mail in allEmails:
		print(bold(green('E-mail found: ')) + mail)

	if len(allEmails) == 0:
		print(bad('Zero links found.'))
	else:
		print(bold(good('Found: ' + str(len(allEmails)))))
		save = input(que('Save them in .txt file? [Y/n]\nUser: '))
		if save in yes:
			f = open(domain + '.' + suffix + '_emails' + '.txt', 'w')
			for l in allEmails:
				f.write('%s\n' % l)
			f.close()
			print(good('Saved.'))
		elif save in no:
			pass
		else:
			print(bad('Enter yes or no.'))
