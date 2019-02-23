#coding: utf-8
#!/usr/bin/python3

from ruamel.yaml import YAML
import platform

#This script stop user of using amaterasu module if he do not have any of lib installed
import_file = open('core/import.yaml').read()
yaml = YAML()
importE = yaml.load(import_file) #import error
bruteforce = importE['BRUTEFORCE']
informationG = importE['INFORMATION_GATHERING']
exploitation = importE['EXPLOITATION']
network = importE['NETWORK']

try:
	from ftplib import FTP
	import ftplib

	bruteforce[0]['ftp_bruteforce'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	bruteforce[0]['ftp_bruteforce'] = 'Error: you need to install ftplib.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import smtplib

	bruteforce[1]['gmail_bruteforce'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	bruteforce[1]['gmail_bruteforce'] = 'Error: you need to install smtplib.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import requests
	import tldextract

	bruteforce[2]['panelfinder'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	bruteforce[2]['panelfinder'] = 'Error: you need to install requests and tldextract.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import paramiko

	bruteforce[3]['ssh_bruteforce'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	bruteforce[3]['ssh_bruteforce'] = 'Error: you need to install paramiko.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	from pwn import *

	exploitation[0]['atgworm'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	exploitation[0]['atgworm'] = 'Error: you need to install pwntools.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import tldextract
	import requests

	informationG[0]['email_extractor'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	informationG[0]['email_extractor'] = 'Error: you need to install requests and tldextract.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import requests

	informationG[1]['honeypotDetector'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	informationG[1]['honeypotDetector'] = 'Error: you need to install requests.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	from ipwhois import IPWhois
	import tldextract

	informationG[2]['ipwhois_extractor'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	informationG[2]['ipwhois_extractor'] = 'Error: you need to install ipwhois and tldextract.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	from xml.etree import ElementTree as etree
	from mp3_tagger import MP3File, VERSION_2
	from PIL.ExifTags import TAGS, GPSTAGS
	from PyPDF2 import PdfFileReader
	from mutagen.mp3 import MP3
	from PIL import Image
	import pefile

	informationG[3]['metadata_extractor'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	informationG[3]['metadata_extractor'] = 'Error: you need to install xml.etree, mp3_tagger, PILLOW, PyPDF2, mutagen.mp3 and pefile.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	from googlesearch import search
	import tldextract
	import requests

	informationG[4]['mysql_vuln_scanner'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	informationG[4]['mysql_vuln_scanner'] = 'Error: you need to install googlesearch, tldextract and requests.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import requests

	informationG[5]['number_verify'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	informationG[5]['number_verify'] = 'Error: you need to install requests.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import tldextract
	import requests

	informationG[6]['spider'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

except ImportError:
	informationG[6]['spider'] = 'Error: you need to install tldextract and requests.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import whois
	import tldextract

	informationG[7]['whois_extractor'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	informationG[7]['whois_extractor'] = 'Error: you need to install whois and tldextract.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import requests
	import dns.resolver
	import tldextract
	import dns.query
	import dns.zone

	network[3]['dns_extractor'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	network[3]['dns_extractor'] = 'Error: you need to install requests, dns and tldextract.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import requests
	import tldextract

	network[1]['reverse_ip'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	network[1]['reverse_ip'] = 'Error: you need to install requests and tldextract.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	import tldextract
	import ipaddress
	import requests

	network[2]['iplocator'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	network[2]['iplocator'] = 'Error: you need to install requests, ipaddress and tldextract.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()

try:
	if platform.system() == 'Windows':
		import requests
		import shodan
	else:
		import nmap
	
	network[0]['network_mapper'] = 'Passed. You can now use this module.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
except ImportError:
	network[0]['network_mapper'] = 'Error: you need to install requests, shodan and nmap.'
	with open('core/import.yaml', 'w') as fl:
		yaml.dump(importE, fl)
	fl.close()
