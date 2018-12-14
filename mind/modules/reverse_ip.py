#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

yes = {'yes', 'y', ''}
no = {'no', 'n'}

def reverse():
	target = input('Enter domain: ')
	url = 'http://api.hackertarget.com/reverseiplookup/?q='
	r = requests.get(url + target)
	n = r.text

	print()
	print(n)
	if n == None:
		print(bad('Zero domains found.'))
	elif sum(item.count('\n') for item in n) > 0:
		for domain in n:
			print(bold(green('Domain found: ')) + item)
		print(good('Found: ' + str(sum(item.count('\n') for item in n))))
		save = input(que('Save them in .txt file? [Y/n]\nUser: '))
		if save in yes:
			f = open(target + 'reverseIP' + '.txt', 'w')
			f.write(n)
			f.close()
			print(good('Saved.'))
		elif save in no:
			pass
		else:
			print(bad('Enter yes or no.'))
	elif 'error check your search parameter' in n:
		print(bad('Check how you wrote the domain.'))
