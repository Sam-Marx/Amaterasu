#coding: utf-8
#!/usr/bin/python3

from mind.modules.main_packages import *

def iploc():
	target = input('Enter IP or domain: ')
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