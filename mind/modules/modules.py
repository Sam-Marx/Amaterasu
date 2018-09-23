#coding: utf-8
#!/usr/bin/python3

import requests
import json
from ipwhois import IPWhois
from huepy import *
import re
import socket
import tldextract

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
