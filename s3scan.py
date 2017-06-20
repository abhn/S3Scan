import re
import sys, os
import httplib2
import boto3, botocore
from BeautifulSoup import BeautifulSoup, SoupStrainer
from optparse import OptionParser
from botocore.client import Config


# Saving myself from passing around these variables
# Sorry!
globalBaseUrl = ""
globalLinkList = []
s3 = None


# https://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# helper functions for coloring
def printGreen(text):
	return bcolors.OKGREEN + text + bcolors.ENDC


def printBlue(text):
	return bcolors.OKBLUE + text + bcolors.ENDC


def printWarning(text):
	return bcolors.WARNING + text + bcolors.ENDC


def printFail(text):
	return bcolors.FAIL + text + bcolors.ENDC

def printScreen(text, color):
	return {
		'green': printGreen(text),
		'blue': printBlue(text),
		'warn': printWarning(text),
		'fail': printFail(text)
	}.get(color, 'blue')


def retrieve_links(url):
	"""Given a url, fetch all hyperlinks on that page and return them as a list"""

	page_source = get_source(url)

	linkList = [] # pun!
	for link in BeautifulSoup(page_source, parseOnlyThese=SoupStrainer('a')):
		if link.has_key('href'):
			linkList.append(link['href'])

	return linkList


def scanner(url):
	"""Look for S3 bucket urls
	Check their permissions and print their security setting
	"""

	if globalBaseUrl in url:
		if url not in globalLinkList:
			# add the current url in the global links pool
			globalLinkList.append(url)

			global s3

			sys.stdout.write(printScreen("[>]Current webpage: " + url + "\n", "blue"))
			
			page_source = get_source(url)

			reg = re.compile('((?:https*)(?::\\/{2}[\\.\\w-]+\\.amazonaws.com)(?:[\\/|\\.]?)(?:[^\\s"]*))')

			# return if empty page
			if page_source == None:
				return

			for bucket in re.findall(reg, page_source):

				sys.stdout.write(printScreen("[*]Found " + bucket + "\n", "blue"))

				# we don't need the complete URL. Just the root of the bucket
				bucketUrl = bucket.split('com/')[0] + 'com/' # TODO this should be a regex

				# grab the username
				# https://abhn.s3.amazonaws.com/randomstring ==> abhn
				if "https" in bucketUrl:
					bucketName = bucketUrl.split('.s3')[0].split('https://')[1]
				else:
					bucketName = bucketUrl.split('.s3')[0].split('http://')[1]

				bucket = s3.Bucket(bucketName)

				sys.stdout.write(printScreen("[>]Testing " + bucketName + "\t", "blue"))

				# flags
				readFlag = 0
				writeFlag = 0
				fullControlFlag = 0
				secureFlag = 0
				# READ :- Any authenticated AWS user can read
				# WRITE :- Any authenticated AWS user ca
				# FULL CONTROL :- Any authenticated AWS user can read/write/delete
				# ClientError :- AccessDenied (Bucket is secure)
				try:
					acl = bucket.Acl()
					for grant in acl.grants:
						if grant['Grantee']['Type'] == "Group" and grant['Permission'] == "READ":
							readFlag = 1
						elif grant['Grantee']['Type'] == "Group" and grant['Permission'] == "WRITE":
							
							writeFlag = 1
						elif grant['Grantee']['Type'] == "Group" and grant['Permission'] == "FULL_CONTROL":
							fullControlFlag = 1
						else:
							pass
					
					# evaluate
					if readFlag and not writeFlag and not fullControlFlag:
						sys.stdout.write(printScreen("[Insecure - Read]", "fail"))
					elif readFlag and writeFlag and not fullControlFlag:
						sys.stdout.write(printScreen("[Insecure - Read+Write]", "fail"))
					elif fullControlFlag:
						sys.stdout.write(printScreen("[Insecure - Full Control]", "fail"))
					else:
						sys.stdout.write(printScreen("[Not Public]", "green"))
					sys.stdout.write('\n')

				except botocore.exceptions.ClientError as e:
					if e.response["Error"]["Code"] == "NoSuchBucket":
						sys.stdout.write(printScreen("[No Such Bucket. Takeover?]\n", "fail"))
					else:
						sys.stdout.write(printScreen("[" + e.response["Error"]["Code"] + "]\n", "green"))




def get_source(url):
	"""Return the source of the supplied url argument"""

	http = httplib2.Http()
	try:
		status, response = http.request(url,
			headers={'User-Agent':' Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0'})
		if status.status == 200:
			return response
		else:
			return None
	except httplib2.HttpLib2Error as e:
		return None


def driver(url):
	"""Scan the current url, retrieve all hyperlinks and then scan those pages recursively"""

	# maintain a list of links from the current page
	currList = []

	page_source = get_source(url)
	if page_source != None:
		links = retrieve_links(url)
		for link in links:
			if len(link) > 0:
				# we hit a relative link
				if globalBaseUrl not in link and link[0] == '/':
					link = globalBaseUrl + link
					scanner(link)
					currList.append(link)
				else:
					scanner(link)
					currList.append(link)
			else:
				continue
		for link in currList:
			driver(link)
	else:
		sys.stdout.write(printScreen("[x]Empty response. Skipping\n", "warn"))


def initiator(globalBaseUrl):
	"""take a url and set up s3 auth. Then call the driver"""

	global s3

	# alternate way to authenticate in else. 
	# use what you prefer
	if True:
		access_key = os.environ.get('AWS_ACCESS_KEY_ID')
		secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

		if access_key is None or secret_key is None:
		    print printWarning("""No access credentials available.
		    	Please export your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
		    	Details: http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html
		    	""")
		    sys.exit(0)

		s3 = boto3.resource('s3', config=Config(signature_version='s3v4'))

	else:
		# If you prefer to supply the credentials here, 
		# make sure you flip the if condition to False
		# and subsitiute the necessary data :)
		s3 = boto3.resource('s3', 
			aws_access_key_id=ACCESS_ID, 
			aws_secret_access_key=ACCESS_KEY,
			config=Config(signature_version='s3v4')
			)

	print printScreen("[>]Initiating...", "blue") 
	print printScreen("[>]Press Ctrl+C to terminate script", "blue")

	scanner(globalBaseUrl)
	driver(globalBaseUrl)

def main():
	parser = OptionParser(usage="$ python ./%prog [-u] url", version="%prog 1.0")

	parser.add_option("-u", "--url", dest="url",
	        help="url to scan")
	parser.add_option("-d", action="store_true", dest="debug",
			help="turn on debug messages")

	(options, args) = parser.parse_args()

	if options.url == None:
		parser.print_help()
		exit(0)

	# debug switch
	if not options.debug:
		# show no traceback. Only exception
		sys.tracebacklimit = 0

	global globalBaseUrl 
	globalBaseUrl = options.url

	# initiate
	initiator(globalBaseUrl)

if __name__ == '__main__':
	main()
