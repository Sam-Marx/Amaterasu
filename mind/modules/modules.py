#coding: utf-8
#!/usr/bin/python3

from xml.etree import ElementTree as etree
from mp3_tagger import MP3File, VERSION_2
from PIL.ExifTags import TAGS, GPSTAGS
from PyPDF2 import PdfFileReader
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
import dns.query
import requests
import dns.zone
import os.path
import zipfile
import shutil
import socket
import pefile
import json
import time
import os
import re

def iploc():
	target = input('Enter domain: ')
	url = 'http://ip-api.com/json/'
	r = requests.get(url + target)
	n = r.text
	jsons = json.loads(n)
	print()
	print(bold(green('IP: ')) + jsons['query'])
	print(bold(green('Status: ')) + jsons['status'])
	print(bold(green('Region: ')) + jsons['regionName'])
	print(bold(green('Country: ')) + jsons['country'])
	print(bold(green('City: ')) + jsons['city'])
	print(bold(green('ISP: ')) + jsons['isp'])
	print(bold(green('Lat,Lon: ')) + str(jsons['lat']) + "," + str(jsons['lon']))
	print(bold(green('ZIPCODE: ')) + jsons['zip'])
	print(bold(green('TimeZone: ')) + jsons['timezone'])
	print(bold(green('AS: ')) + jsons['as'])

def reverse():
	target = input('Enter domain: ')
	url = 'http://api.hackertarget.com/reverseiplookup/?q='
	r = requests.get(url + target)
	n = r.text
	print()
	print(n)

def spider():
	target = input('Enter URL: ')
	if target.startswith('http://'):
		r = requests.get(target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(r.text)
		for link in links:
			print(bold(purple('Link found: ')) + link)
	elif target.startswith('https://'):
		r = requests.get(target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(r.text)
		for link in links:
			print(bold(purple('Link found: ')) + link)
	else:
		r = requests.get('http://' + target)
		link_find = re.compile('href="(.*?)"')
		links = link_find.findall(r.text)
		for link in links:
			print(bold(purple('Link found: ')) + link)

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
				if whname == None:
					print(bold(red("NAME ERROR: " )) + "Amaterasu can't find the name.")
				else:
					print(bold(green('Name: ' )) + whname)
				print(bold(green('IP: ')) + addr)
				if whdesc == None:
					print(bold(red("DESCRIPTION ERROR: ")) + "Amaterasu can't find the description.")
				else:
					print(bold(green('Description: ')) + whdesc)
				if whcount == None:
					print(bold(red("Country ERROR: ")) + "Amaterasu can't find the country.")
				else:
					print(bold(green("Country: ")) + whcount)
				if whstate == None:
					print(bold(red("STATE ERROR: ")) + "Amaterasu can't find the state.")
				else:
					print(bold(green('State: ')) + whstate)
				if whcity == None:
					print(bold(red("CITY ERROR: ")) + "Amaterasu can't find the city.")
				else:
					print(bold(green('City: ')) + whcity)
				if whadd == None:
					print(bold(red("ADDRESS ERROR: ")) + "Amaterasu can't find the address.")
				else:
					print(bold(green('Address: ')) + whadd)
				if whemail == None:
					print(bold(red("ABUSE E-MAIL ERROR: " )) + "Amaterasu can't find the abuse e-mail.")
				else:
					print(bold(green('Abuse e-mail: ')) + whemail)
				if whcidr == None:
					print(bold(red("CIDR ERROR: ")) + "Amaterasu can't find the CIDR.")
				else:
					print(bold(green('CIDR: ')) + whcidr)
				if whasncidr == None:
					print(bold(red("ASN CIDR ERROR: ")) + "Amaterasu can't find the ASN_CIDR.")
				else:
					print(bold(green('ASN CIDR: ')) + whasncidr)
				if whasn == None:
					print(bold(red("ASN ERROR: ")) + "Amaterasu can't find the ASN.")
				else:
					print(bold(green('ASN: ')) + whasn)

		if target.startswith('http://'):
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
				print(bold(red("NAME ERROR: " )) + "Amaterasu can't find the name.")
			else:
				print(bold(green('Name: ' )) + whname)
			if whdesc == None:
				print(bold(red("DESCRIPTION ERROR: ")) + "Amaterasu can't find the description.")
			else:
				print(bold(green('Description: ')) + whdesc)
			if whcount == None:
				print(bold(red("Country ERROR: ")) + "Amaterasu can't find the country.")
			else:
				print(bold(green("Country: ")) + whcount)
			if whstate == None:
				print(bold(red("STATE ERROR: ")) + "Amaterasu can't find the state.")
			else:
				print(bold(green('State: ')) + whstate)
			if whcity == None:
				print(bold(red("CITY ERROR: ")) + "Amaterasu can't find the city.")
			else:
				print(bold(green('City: ')) + whcity)
			if whadd == None:
				print(bold(red("ADDRESS ERROR: ")) + "Amaterasu can't find the address.")
			else:
				print(bold(green('Address: ')) + whadd)
			if whemail == None:
				print(bold(red("ABUSE E-MAIL ERROR: " )) + "Amaterasu can't find the abuse e-mail.")
			else:
				print(bold(green('Abuse e-mail: ')) + whemail)
			if whcidr == None:
				print(bold(red("CIDR ERROR: ")) + "Amaterasu can't find the CIDR.")
			else:
				print(bold(green('CIDR: ')) + whcidr)
			if whasncidr == None:
				print(bold(red("ASN CIDR ERROR: ")) + "Amaterasu can't find the ASN_CIDR.")
			else:
				print(bold(green('ASN CIDR: ')) + whasncidr)
			if whasn == None:
				print(bold(red("ASN ERROR: ")) + "Amaterasu can't find the ASN.")
			else:
				print(bold(green('ASN: ')) + whasn)

		elif target.startswith('https://'):
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
				print(bold(red("NAME ERROR: " )) + "Amaterasu can't find the name.")
			else:
				print(bold(green('Name: ' )) + whname)
			if whdesc == None:
				print(bold(red("DESCRIPTION ERROR: ")) + "Amaterasu can't find the description.")
			else:
				print(bold(green('Description: ')) + whdesc)
			if whcount == None:
				print(bold(red("Country ERROR: ")) + "Amaterasu can't find the country.")
			else:
				print(bold(green("Country: ")) + whcount)
			if whstate == None:
				print(bold(red("STATE ERROR: ")) + "Amaterasu can't find the state.")
			else:
				print(bold(green('State: ')) + whstate)
			if whcity == None:
				print(bold(red("CITY ERROR: ")) + "Amaterasu can't find the city.")
			else:
				print(bold(green('City: ')) + whcity)
			if whadd == None:
				print(bold(red("ADDRESS ERROR: ")) + "Amaterasu can't find the address.")
			else:
				print(bold(green('Address: ')) + whadd)
			if whemail == None:
				print(bold(red("ABUSE E-MAIL ERROR: " )) + "Amaterasu can't find the abuse e-mail.")
			else:
				print(bold(green('Abuse e-mail: ')) + whemail)
			if whcidr == None:
				print(bold(red("CIDR ERROR: ")) + "Amaterasu can't find the CIDR.")
			else:
				print(bold(green('CIDR: ')) + whcidr)
			if whasncidr == None:
				print(bold(red("ASN CIDR ERROR: ")) + "Amaterasu can't find the ASN_CIDR.")
			else:
				print(bold(green('ASN CIDR: ')) + whasncidr)
			if whasn == None:
				print(bold(red("ASN ERROR: ")) + "Amaterasu can't find the ASN.")
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
				print(bold(red("NAME ERROR: " )) + "Amaterasu can't find the name.")
			else:
				print(bold(green('Name: ' )) + whname)
			if whdesc == None:
				print(bold(red("DESCRIPTION ERROR: ")) + "Amaterasu can't find the description.")
			else:
				print(bold(green('Description: ')) + whdesc)
			if whcount == None:
				print(bold(red("Country ERROR: ")) + "Amaterasu can't find the country.")
			else:
				print(bold(green("Country: ")) + whcount)
			if whstate == None:
				print(bold(red("STATE ERROR: ")) + "Amaterasu can't find the state.")
			else:
				print(bold(green('State: ')) + whstate)
			if whcity == None:
				print(bold(red("CITY ERROR: ")) + "Amaterasu can't find the city.")
			else:
				print(bold(green('City: ')) + whcity)
			if whadd == None:
				print(bold(red("ADDRESS ERROR: ")) + "Amaterasu can't find the address.")
			else:
				print(bold(green('Address: ')) + whadd)
			if whemail == None:
				print(bold(red("ABUSE E-MAIL ERROR: " )) + "Amaterasu can't find the abuse e-mail.")
			else:
				print(bold(green('Abuse e-mail: ')) + whemail)
			if whcidr == None:
				print(bold(red("CIDR ERROR: ")) + "Amaterasu can't find the CIDR.")
			else:
				print(bold(green('CIDR: ')) + whcidr)
			if whasncidr == None:
				print(bold(red("ASN CIDR ERROR: ")) + "Amaterasu can't find the ASN_CIDR.")
			else:
				print(bold(green('ASN CIDR: ')) + whasncidr)
			if whasn == None:
				print(bold(red("ASN ERROR: ")) + "Amaterasu can't find the ASN.")
			else:
				print(bold(green('ASN: ')) + whasn)
	except Exception:
		pass

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

	if target.startswith('https://'):
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
			print(bad('Query failed > NS records.'))

		try:
			print()
			a = dnsr.query(target, 'A')
			for rs in a:
				print(bold(green('A records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > A records.'))

		try:
			print()
			mx = dnsr.query(target, 'MX')
			for rs in mx:
				print(bold(green('MX records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > MX records.'))

		try:
			print()
			txt = dnsr.query(target, 'TXT')
			for spf in txt:
				print(bold(green('SPF records: ')) + str(spf))
		except dns.exception.DNSException:
			print(bad('Query failed > SPF records.'))

	elif target.startswith('http://'):
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
			print(bad('Query failed > NS records.'))

		try:
			print()
			a = dnsr.query(target, 'A')
			for rs in a:
				print(bold(green('A records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > A records.'))

		try:
			print()
			mx = dnsr.query(target, 'MX')
			for rs in mx:
				print(bold(green('MX records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > MX records.'))

		try:
			print()
			txt = dnsr.query(target, 'TXT')
			for spf in txt:
				print(bold(green('SPF records: ')) + str(spf))
		except dns.exception.DNSException:
			print(bad('Query failed > SPF records.'))

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
			print(bad('Query failed > NS records.'))

		try:
			print()
			a = dnsr.query(target, 'A')
			for rs in a:
				print(bold(green('A records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > A records.'))

		try:
			print()
			mx = dnsr.query(target, 'MX')
			for rs in mx:
				print(bold(green('MX records: ')) + str(rs))
		except dns.exception.DNSException:
			print(bad('Query failed > MX records.'))

		try:
			print()
			txt = dnsr.query(target, 'TXT')
			for spf in txt:
				print(bold(green('SPF records: ')) + str(spf))
		except dns.exception.DNSException:
			print(bad('Query failed > SPF records.'))

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
