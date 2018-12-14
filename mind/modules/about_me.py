#coding: utf-8
#!/usr/bin/python3

from huepy import *
import platform

if platform.system() == 'Windows':
	import ctypes
	import wmi
else:
	pass

def showUsers(windows = False, linux = False):
	if windows == True:
		DRIVE_TYPES = {
		0 : 'Unknown',
		1 : 'No root directory',
		2 : 'Removable disk',
		3 : 'Local disk',
		4 : 'Network drive',
		5 : 'Compact disc',
		6 : 'RAM disk'
		}

		c = wmi.WMI()
		for d in c.Win32_LogicalDisk():
			if d.size != None:
				print(bold(green('Drives')))
				print('\t' + bold(good(d.Caption)), 'is {0:.2f}% free'.format(100*float(d.FreeSpace)/float(d.Size)))
				print('\t' + bold(good(bold(green('Drive type: ') + DRIVE_TYPES[d.DriveType]))))
		print()
		for gp in c.Win32_Group():
			print(bold(green('Group: ')) + gp.Caption)
			for user in gp.associators(wmi_result_class='Win32_UserAccount'):
				print('\t' + bold(good(bold(green('User: ') + user.Caption))))
		print()
		for iface in c.Win32_NetworkAdapterConfiguration(IPEnabled=1):
			print(bold(green('Interface description: ')) + iface.Description)
			print(bold(green('MAC address: ')) + iface.MACAddress)
			for ipaddr in iface.IPAddress:
				print('\t' + bold(good(bold(green('IP address: ') + ipaddr))))

	elif linux == True:
		pass

def aboutme():
	print(bold(green('Operating System: ') + platform.system()))
	print(bold(green("System's release: ") + platform.release()))
	print(bold(green("System's version: ") + platform.version()))
	print(bold(green('Machine type: ') + platform.machine()))
	print(bold(green('Processor: ') + platform.processor()))
	print()
	if platform.system() == 'Windows':
		showUsers(windows = True)
	elif platform.system() == 'Linux':
		showUsers(linux = True)
