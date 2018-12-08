#coding: utf-8
#!/usr/bin/python3

from xml.etree import ElementTree as etree
from mp3_tagger import MP3File, VERSION_2
from PIL.ExifTags import TAGS, GPSTAGS
from PyPDF2 import PdfFileReader
from googlesearch import search
from bs4 import BeautifulSoup
from datetime import datetime
from ipwhois import IPWhois
from mutagen.mp3 import MP3
from pprint import pprint
from ftplib import FTP
from PIL import Image
from huepy import *
import dns.resolver
import tldextract
import ipaddress
import dns.query
import requests
import platform
import dns.zone
import os.path
import zipfile
import shutil
import socket
import shodan
import pefile
import json
import nmap
import time
import os
import re

yes = {'yes', 'y', ''}
no = {'no', 'n'}

def iploc():
	target = input('Enter domain: ')
	target = socket.gethostbyname(target)
	r = requests.get('https://ipapi.co/' + target + '/json/')
	n = r.text
	jsons = json.loads(n)
	print()
	print(bold(green('IP: ')) + str(jsons['ip']))
	print(bold(green('City: ')) + str(jsons['city']))
	print(bold(green('Region: ')) + str(jsons['region']))
	print(bold(green('Region Code: ')) + str(jsons['region_code']))
	print(bold(green('Country: ')) + str(jsons['country_name']))
	print(bold(green('Country Code: ')) + str(jsons['country']))
	print(bold(green('Postal: ')) + str(jsons['postal']))
	print(bold(green('Latitude: ')) + str(jsons['latitude']))
	print(bold(green('Longitude: ')) + str(jsons['longitude']))
	print(bold(green('Timezone: ')) + str(jsons['timezone']))
	print(bold(green('UTC offset: ')) + str(jsons['utc_offset']))
	print(bold(green('Country calling code: ')) + str(jsons['country_calling_code']))
	print(bold(green('Currency: ')) + str(jsons['currency']))
	print(bold(green('Languages: ')) + str(jsons['languages']))
	print(bold(green('ASN: ')) + str(jsons['asn']))
	print(bold(green('Organization: ')) + str(jsons['org']))
	print(bold(green('Aditional info:')))
	if ipaddress.ip_address(target).is_multicast == True:
		print('\t' + bold(good('The IP is reserved for multicast use.')))
	if ipaddress.ip_address(target).is_private == True:
		print('\t' + bold(good('The IP is allocated for public networks.')))
	if ipaddress.ip_address(target).is_global == True:
		print('\t' + bold(good('The IP is allocated for private networks.')))

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
		print(good('Domains found: ' + str(sum(item.count('\n') for item in n))))
		save = input(que('Save them in .txt file? [Y/n]\nUser: '))
		if save in yes:
			f = open(target + '.txt', 'w')
			f.write(n)
			f.close()
			print(good('Saved.'))
		elif save in no:
			pass
		else:
			print(bad('Enter yes or no.'))
	elif 'error check your search parameter' in n:
		print(bad('Check how you wrote the domain.'))

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

def whois():
	target = input('Enter URL: ')

	try:
		if target == '':
			file = input('Enter file with domains: ')
			filelist = open(file, 'r')

			for domain in filelist.readlines():
				domain = domain.strip()
				addr = socket.gethostbyname(domain)
				obj = IPWhois(addr)
				res = obj.lookup()

				whname = res["nets"][0]['name']
				whdesc = res["nets"][0]['description']
				whemail = res["nets"][0]['abuse_emails']
				whcount = res["nets"][0]['country']
				whstate = res["nets"][0]['state']
				whcidr = res["nets"][0]['cidr']
				whcity = res["nets"][0]['city']
				whadd = res["nets"][0]['address']
				whasncidr = res['asn_cidr']
				whasn = res['asn']
				whasndt = res['asn_date']
				whasnreg = res['asn_registry']

				print()
				print(bold(green('Domain: ')) + domain)
				if whname == None:
					pass
				else:
					print(bold(green('Name: ' )) + whname)
				print(bold(green('IP: ')) + addr)
				if whdesc == None:
					pass
				else:
					print(bold(green('Description: ')) + whdesc)
				if whcount == None:
					pass
				else:
					print(bold(green("Country: ")) + whcount)
				if whstate == None:
					pass
				else:
					print(bold(green('State: ')) + whstate)
				if whcity == None:
					pass
				else:
					print(bold(green('City: ')) + whcity)
				if whadd == None:
					pass
				else:
					print(bold(green('Address: ')) + whadd)
				if whemail == None:
					pass
				else:
					print(bold(green('Abuse e-mail: ')) + whemail)
				if whcidr == None:
					pass
				else:
					print(bold(green('CIDR: ')) + whcidr)
				if whasncidr == None:
					pass
				else:
					print(bold(green('ASN CIDR: ')) + whasncidr)
				if whasn == None:
					pass
				else:
					print(bold(green('ASN: ')) + whasn)

		elif target.startswith('http://') or target.startswith('https://'):
			ext = tldextract.extract(target)
			domain = ext.domain
			suffix = ext.suffix

			fullsite = domain + '.' + suffix

			addr = socket.gethostbyname(fullsite)
			obj = IPWhois(addr)
			res = obj.lookup()

			whname = res["nets"][0]['name']
			whdesc = res["nets"][0]['description']
			whemail = res["nets"][0]['abuse_emails']
			whcount = res["nets"][0]['country']
			whstate = res["nets"][0]['state']
			whcidr = res["nets"][0]['cidr']
			whcity = res["nets"][0]['city']
			whadd = res["nets"][0]['address']
			whasncidr = res['asn_cidr']
			whasn = res['asn']
			whasndt = res['asn_date']
			whasnreg = res['asn_registry']

			print()
			if whname == None:
				pass
			else:
				print(bold(green('Name: ' )) + whname)
			if whdesc == None:
				pass
			else:
				print(bold(green('Description: ')) + whdesc)
			if whcount == None:
				pass
			else:
				print(bold(green("Country: ")) + whcount)
			if whstate == None:
				pass
			else:
				print(bold(green('State: ')) + whstate)
			if whcity == None:
				pass
			else:
				print(bold(green('City: ')) + whcity)
			if whadd == None:
				pass
			else:
				print(bold(green('Address: ')) + whadd)
			if whemail == None:
				pass
			else:
				print(bold(green('Abuse e-mail: ')) + whemail)
			if whcidr == None:
				pass
			else:
				print(bold(green('CIDR: ')) + whcidr)
			if whasncidr == None:
				pass
			else:
				print(bold(green('ASN CIDR: ')) + whasncidr)
			if whasn == None:
				pass
			else:
				print(bold(green('ASN: ')) + whasn)
		else:
			addr = socket.gethostbyname(target)
			obj = IPWhois(addr)
			res = obj.lookup()

			whname = res["nets"][0]['name']
			whdesc = res["nets"][0]['description']
			whemail = res["nets"][0]['abuse_emails']
			whcount = res["nets"][0]['country']
			whstate = res["nets"][0]['state']
			whcidr = res["nets"][0]['cidr']
			whcity = res["nets"][0]['city']
			whadd = res["nets"][0]['address']
			whasncidr = res['asn_cidr']
			whasn = res['asn']
			whasndt = res['asn_date']
			whasnreg = res['asn_registry']

			print()
			if whname == None:
				pass
			else:
				print(bold(green('Name: ' )) + whname)
			if whdesc == None:
				pass
			else:
				print(bold(green('Description: ')) + whdesc)
			if whcount == None:
				pass
			else:
				print(bold(green("Country: ")) + whcount)
			if whstate == None:
				pass
			else:
				print(bold(green('State: ')) + whstate)
			if whcity == None:
				pass
			else:
				print(bold(green('City: ')) + whcity)
			if whadd == None:
				pass
			else:
				print(bold(green('Address: ')) + whadd)
			if whemail == None:
				pass
			else:
				print(bold(green('Abuse e-mail: ')) + whemail)
			if whcidr == None:
				pass
			else:
				print(bold(green('CIDR: ')) + whcidr)
			if whasncidr == None:
				pass
			else:
				print(bold(green('ASN CIDR: ')) + whasncidr)
			if whasn == None:
				pass
			else:
				print(bold(green('ASN: ')) + whasn)
	except Exception:
		pass
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

def subdomain():
	target = input('Enter domain: ')
	if target.startswith('http://'):
		subdomains = []

		r = requests.get('https://crt.sh/?q=%.{}&output=json'.format(target))

		if r.status_code != 200:
			print(bad('crt.sh not available.'))
			pass

		js = json.loads('[{}]'.format(r.text.replace('}{', '},{')))

		for (key, value) in enumerate(js):
			subdomains.append(value['name_value'])

		subdomains = sorted(set(subdomains))

		for subdomain in subdomains:
			print(good('Subdomain found: ' + subdomain))

	elif target.startswith('https://'):
		subdomains = []

		r = requests.get('https://crt.sh/?q=%.{}&output=json'.format(target))

		if r.status_code != 200:
			print(bad('crt.sh not available.'))
			pass

		js = json.loads('[{}]'.format(r.text.replace('}{', '},{')))

		for (key, value) in enumerate(js):
			subdomains.append(value['name_value'])

		subdomains = sorted(set(subdomains))

		for subdomain in subdomains:
			print(good('Subdomain found: ' + subdomain))

	else:
		subdomains = []

		r = requests.get('https://crt.sh/?q=%.{}&output=json'.format(target))

		if r.status_code != 200:
			print(bad('crt.sh not available.'))
			pass

		js = json.loads('[{}]'.format(r.text.replace('}{', '},{')))

		for (key, value) in enumerate(js):
			subdomains.append(value['name_value'])

		subdomains = sorted(set(subdomains))

		for subdomain in subdomains:
			print(good('Subdomain found: ' + subdomain))

def dns_ex():
	target = input('Enter URL: ')
	dnsr = dns.resolver

	if target.startswith('https://') or target.startswith('http://'):
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix

		target = domain + '.' + suffix

		try:
			print()
			ns = dnsr.query(target, 'NS')
			for rs in ns:
				print(bold(green('NS records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed: NS records.'))

		try:
			print()
			a = dnsr.query(target, 'A')
			for rs in a:
				print(bold(green('A records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed: A records.'))

		try:
			print()
			mx = dnsr.query(target, 'MX')
			for rs in mx:
				print(bold(green('MX records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed: MX records.'))

		try:
			print()
			txt = dnsr.query(target, 'TXT')
			for spf in txt:
				print(bold(green('SPF records: ')) + str(spf))
		except dns.exception.DNSException:
			print(bad('Query failed: SPF records.'))

	else:
		ext = tldextract.extract(target)
		domain = ext.domain
		suffix = ext.suffix

		target = domain + '.' + suffix

		try:
			print()
			ns = dnsr.query(target, 'NS')
			for rs in ns:
				print(bold(green('NS records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed: NS records.'))

		try:
			print()
			a = dnsr.query(target, 'A')
			for rs in a:
				print(bold(green('A records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed: A records.'))

		try:
			print()
			mx = dnsr.query(target, 'MX')
			for rs in mx:
				print(bold(green('MX records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed: MX records.'))

		try:
			print()
			txt = dnsr.query(target, 'TXT')
			for spf in txt:
				print(bold(green('SPF records: ')) + str(spf))
		except dns.exception.DNSException:
			print(bad('Query failed: SPF records.'))

def ftp_brute():
	target = input('Enter IP or domain: ')
	username = input('Enter USERNAME wordlist: ')
	password = input('Enter PASSWORD wordlist: ')

	ftp = FTP(target)
	print()
	answers = {'230 Anonymous access granted, restrictions apply', '230 Login successfull.', 'Guest login ok, access restrictions apply.', 'User anonymous logged in.'}

	try:
		if ftp.login() in answers:
			print(good('Anonymous login is open.'))
			print(good('Username: anonymous'))
			print(good('Password: anonymous@'))
			ftp.close()
		else:
			ftp.close()
	except:
		ftp.close()
		pass

	try:
		usernames = open(username)
		passwords = open(password)

		answers = {'230 Anonymous access granted, restrictions apply', '230 Login successfull.', 'Guest login ok, access restrictions apply.', 'User anonymous logged in.'}
		for user in usernames.readlines():
			for passw in passwords.readlines():
				user = user.strip()
				passw = passw.strip()
				ftp = FTP(target)

				try:
					if ftp.login(user, passw) in answers:
						print()
						print(good('Success.'))
						print(good('Username: ' + user))
						print(good('Password: ' + passw))
						ftp.close()
						#break
					else:
						print()
						print(bad('Failed.'))
						print(bad('Username failed: ' + user))
						print(bad('Password failed: ' + passw))
						ftp.close()
				except Exception as e:
					print()
					print(bad('Failed: {}'.format(e)))
					print(bad('Username failed: ' + user))
					print(bad('Password failed: ' + passw))
					ftp.close()
	except Exception as e:
		print(bad('Bruteforce failed: ' + e))
		ftp.quit()

def mapper():
	if 'Windows' in platform.system() or 'Darwin' in platform.system():
		target = input('Enter IP or URL: ')
		try:
			getPorts = requests.get('https://api.hackertarget.com/nmap/?q=' + target)
			print(getPorts.text)
		except Exception as e:
			print(bad('Got an error: ' + str(e)))
		target = socket.gethostbyname(target)
		print()
		checkShodan = input(que('Try to get with Shodan (Y/n)? '))
		if checkShodan.lower() in yes:
			try:
				shodan_api = 'bnKG6By87G8PJwao1DOzX3TzgCwNwxF9'
				api = shodan.Shodan(shodan_api)
				host = api.host(target)
				print()
				print(good('IP: {}'.format(host['ip_str'])))
				print(good('Operating System: {}'.format(host.get('os', 'n/a'))))
				for item in host['data']:
					print(good('Port: {}'.format(item['port'])))
					print(good('Banner: {}'.format(item['data'])))
				print()
				print(good('Organization: {}'.format(host.get('org', 'n/a'))))
			except Exception as e:
				print()
				print(bad('Failed with Shodan: {}'.format(e)))
				pass
			except shodan.APIError as e:
				print(bad('Error with API: {}'.format(e)))
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
			print(good('Host: %s (%s)' % (host, nm[host].hostname())))
			print(good('State: %s' % nm[host].state()))
		nm.scan(target, arguments='-O')
		if 'osclass' in nm[target]:
			for osclass in nm[target]['osclass']:
				print(good('OS type: %s' % osclass['type']))
				print(good('OS vendor: %s' % osclass['vendor']))
				print(good('OS family: %s' % osclass['osfamily']))
				print(good('OS gen: %s' % osclass['osgen']))
				print(good('OS accuracy: %s' % osclass['accuracy']))
		else:
			print()
			checkShodan = input(que('Try to get with Shodan (Y/n)? '))
			if checkShodan.lower() in yes:
				try:
					shodan_api = 'bnKG6By87G8PJwao1DOzX3TzgCwNwxF9'
					api = shodan.Shodan(shodan_api)
					host = api.host(target)
					print()
					print(good('IP: {}'.format(host['ip_str'])))
					print(good('Operating System: {}'.format(host.get('os', 'n/a'))))
					for item in host['data']:
						print(good('Port: {}'.format(item['port'])))
						print(good('Banner: {}'.format(item['data'])))
					print()
					print(good('Organization: {}'.format(host.get('org', 'n/a'))))
				except Exception as e:
					print()
					print(bad('Failed with Shodan: {}'.format(e)))
					pass
				except shodan.APIError as e:
					print(bad('Error with API: {}'.format(e)))
		for proto in nm[host].all_protocols():
			print(good('Protocol: ' + proto))

			rport = nm[host][proto].keys()
			rport = list(rport)
			rport.sort()
			for p in rport:
				print(good('Port: %s\tStatus: %s' % (p, nm[host][proto][p]['state'])))

def metadata():
	print('Only .MP3, .JPG, .JPEG, .PNG, .DOCX and .PDF.')

	try:
		file = input(que('Enter file location: '))

		if file.endswith('.jpg'):
			print()
			try:
				for (tag, value) in Image.open(file)._getexif().items():
					print('%s = %s' % (TAGS.get(tag), value))
			except Exception as e:
				print('Could not get any information.')

		if file.endswith('.jpeg'):
			print()
			try:
				for (tag, value) in Image.open(file)._getexif().items():
					print('%s = %s' % (TAGS.get(tag), value))
			except Exception as e:
				print('Could not get any information.')

		if file.endswith('.png'):
			print()
			try:
				for (tag, value) in Image.open(file)._getexif().items():
					print('%s = %s' % (TAGS.get(tag), value))
			except Exception as e:
				print('Could not get any information.')

		elif file.endswith('.pdf'):
			print()
			stat = os.stat(file)
			try:
				if 'Linux' in platform.system() or 'darwin' in platform.system():
					print(bold(green('Change time: ')) + stat.st_ctime)
				elif 'Windows' in platform.system():
					print(bold(green('Creation date: ')) + time.ctime(os.path.getctime(file)))
				else:
					print(bad('Cant extract creation date. Platform {} is unsupported.'.format(platform.system())))
				print(bold(green('Access time: ')) + time.ctime(os.path.getatime(file)))
				print(bold(green('Modified time: ')) + time.ctime(os.path.getmtime(file)))
				with open(file, 'rb') as f:
					pdf = PdfFileReader(f)
					info = pdf.getDocumentInfo()
					number = pdf.getNumPages()

					try:
						author = info.author
						print(bold(green('Author: ')) + str(author))
					except Exception:
						pass
					try:
						creator = info.creator
						print(bold(green('Creator: ')) + str(creator))
					except Exception:
						pass
					try:
						producer = info.producer
						print(bold(green('Producer: ')) + str(producer))
					except Exception:
						pass
					try:
						subject = info.subject
						print(bold(green('Subject: ')) + str(subject))
					except Exception:
						pass
					try:
						title = info.title
						print(bold(green('Title: ')) + str(title))
					except Exception:
						pass
					
					print(bold(green('Number of pages: ')) + str(number))
					print(bold(green('File size: ')) + str(stat.st_size))
					print(bold(green('File mode: ')) + str(stat.st_mode))
					print(bold(green('File inode: ')) + str(stat.st_ino))
					print(bold(green('Group ID: ')) + str(stat.st_gid))
					print(bold(green('Owner USER ID: ')) + str(stat.st_uid))
			except Exception as e:
				print(e)

		elif file.endswith('.mp3'):
			print()
			try:
				mp3 = MP3File(file)
				tags = mp3.get_tags()
				
				mp3.set_version(VERSION_2)

				title = mp3.song
				artist = mp3.artist
				alb = mp3.album
				trac = mp3.track
				genr = mp3.genre
				year = mp3.year
				band = mp3.band
				composer = mp3.composer
				copyright = mp3.copyright
				publisher = mp3.publisher
				url = mp3.url
				comment = mp3.comment

				audio = MP3(file)
				length = audio.info.length
				bitrate = audio.info.bitrate
				channels = audio.info.channels

				print(bold(green('Title: ')) + str(title))
				print(bold(green('Artist: ')) + str(artist))
				print(bold(green('Band: ')) + str(band))
				print(bold(green('Composer: ')) + str(composer))
				print(bold(green('Publisher: ')) + str(publisher))
				print(bold(green('URL: ')) + str(url))
				print(bold(green('Copyright: ')) + str(copyright))
				print(bold(green('Album: ')) + str(alb))
				print(bold(green('Track: ')) + str(trac))
				print(bold(green('Genre: ')) + str(genr))
				print(bold(green('Year: ')) + str(year))
				print(bold(green('Comment: ')) + str(comment))
				print(bold(green('Bitrate: ')) + str(bitrate))
				print(bold(green('Length: ')) + str(length))
				print(bold(green('Channels: ')) + str(channels))
			except Exception as e:
				print(e)

		elif file.endswith('.docx'):
			print()
			zipfile.is_zipfile(file)
			zfile = zipfile.ZipFile(file)

			#extract key elements for processing
			core_xml = etree.fromstring(zfile.read('docProps/core.xml'))
			app_xml = etree.fromstring(zfile.read('docProps/app.xml'))

			core_map = {
			'title' : 'Title',
			'subject' : 'Subject',
			'creator' : 'Author(s)',
			'keywords' : 'Keywords',
			'description' : 'Description',
			'lastModifiedBy' : 'Last Modified By',
			'modified' : 'Modified Date',
			'created' : 'Created Date', 
			'category' : 'Category',
			'contentStatus' : 'Status',
			'revision' : 'Revision'
			}

			for element in core_xml.getchildren():
				for key, title in core_map.items():
					if key in element.tag:
						if 'date' in title.lower():
							try:
								text = dt.strptime(element.text, '%Y-%m-%dT%H:%M:%SZ')
							except Exception as e:
								pass
						else:
							text = element.text
						print(bold(green('{}: '.format(title))) + '{}'.format(text))

			app_map = {
			'TotalTime' : 'Edit Time (minutes)',
			'Pages' : 'Page Count',
			'Words' : 'Word Count',
			'Characters' : 'Character Count',
			'Lines' : 'Line Count',
			'Paragraphs' : 'Paragraph Count',
			'Company' : 'Company',
			'HyperlinkBase' : 'Hyperlink Base',
			'Slides' : 'Slide count',
			'Notes' : 'Note count',
			'HiddenSlides' : 'Hidden Slide Count'
			}

			for element in app_xml.getchildren():
				for key, title in app_map.items():
					if 'date' in title.lower():
						try:
							text = dt.strptime(element.text, '%Y-%m-%dT%H:%M:%SZ')
						except Exception as e:
							pass
					else:
						text = element.text
					print(bold(green('{}: '.format(title))) + '{}'.format(text))

		elif file.endswith('.exe'):
			stat = os.stat(file)

			link = pefile.PE(file)
			stat = os.stat(file)
			#print(print_info(encoding='utf-8'))
			imp = link.get_imphash()
			errors = link.get_warnings()
			relocs = link.has_relocs()
			checksum = link.verify_checksum()
			strings = link.get_resources_strings()
			print()
			print(bold(green('Hash of Import Address Table (IAT): ')) + imp)
			print(bold(green('Errors: ')) + str(errors))
			print(bold(green('Has relocation directory: ')) + str(relocs))
			print(bold(green('Checksum: ')) + str(checksum))
			print(bold(green('File size: ')) + str(stat.st_size))
			print()
			print(bold(red('Strings')))
			for string in strings:
				print(bold(green('String: ')) + string)
			print()
			print(bold(red('Directory Entry Import')))
			for entry in link.DIRECTORY_ENTRY_IMPORT:
				print('\t' + entry.dll.decode('utf-8'))

	except KeyboardInterrupt:
		print()
		#print('Soon.')
		#target = input(strike(que('Enter target: ')))

def findPanel():
	try:
		target = input('Enter domain: ')
		file = input('Enter panel list: ')

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
					print(bold(good('Login panel found: ' + target + '/' + a)))
					panelsFound.append(target + '/' + a)

				elif r.status_code == 404:
					print(bold(bad('Login panel not found: ' + target + '/' + a)))
	except KeyboardInterrupt:
		print()
		for p in panelsFound:
			print(bold(good('Panel: ')) + p)
		print(bold(good('Found: ' + str(len(panelsFound)))))
