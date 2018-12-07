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
