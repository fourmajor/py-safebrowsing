from apiclient.discovery import build
from argparse import ArgumentParser
from googleapiclient.errors import HttpError
from httplib2 import ServerNotFoundError
import logging
from os.path import exists
from pprint import pprint
import re
from time import sleep

APIFILENAME = 'google_api_key'

# "The HTTP POST request can include up to 500 URLs"
# https://developers.google.com/safe-browsing/v4/lookup-api
CHUNKSIZE = 500

# url matching regex from https://stackoverflow.com/a/6883094/6423354
# this regex should be improved, for example to match unicode characters
urlRegex = re.compile('^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$', re.IGNORECASE)

logger = logging.getLogger('safeBrowsing')
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

# get the API key from file
try:
    apiKeyFile = open(APIFILENAME)
    apiKey = apiKeyFile.read()
    apiKeyFile.close()
except FileNotFoundError:
    fileNotFoundErrorMessage = '''You must include your Google API key in the file 
{}. To get a Google API key, follow these instructions: 
https://support.google.com/cloud/answer/6158862?hl=en&ref_topic=6262490'''
    fileNotFoundErrorMessage = fileNotFoundErrorMessage.format(APIFILENAME)
    logger.error(fileNotFoundErrorMessage)
    quit()
except IOError:
    logger.error('API key file {} not readable, quitting')
    quit()
except UnicodeDecodeError:
    logger.error('API key file has a unicode error. Is it the correct format? Quitting.')
    quit()

# process input
parser = ArgumentParser(description = \
    'Check URLs against the Google Safe Browsing API')
parser.add_argument('url', nargs = '+',
                    help = 'domain, url, or file containing one of the former')
args = parser.parse_args()
urlArgs = list(set(args.url)) # only unique args

# used to add protocol part to url
def addProtocol(url, protocol):
    if re.match('.+://.+', url):
        return url
    else:
        return '{}://{}'.format(protocol, url)

def isUrlOrDomain(url, regex):
    return regex.match(url) or regex.match(addProtocol(url, 'http')) or \
        regex.match(addProtocol(url, 'https'))

urls = []
for urlArg in urlArgs:
    # argument from command line is a file
    if exists(urlArg):
        try:
            with open(urlArg) as urlFile:
                try:
                    for line in urlFile:
                        # should check if it can properly decode the file
                        # (text or binary?)
                        if isUrlOrDomain(line, urlRegex):
                            urls.append(line.strip())
                        else:
                            logger.warn('in file {}, {} is not a url, skipping'.format(
                                urlArg, line))
                except UnicodeDecodeError:
                    logger.error('''file {} is not the correct format, cannot read 
some or all of it as URLs'''.format(urlArg))
        except IOError:
            logger.warn('{} is a file but is not readable, skipping')
    # if it's not a file, is the argument a URL?
    elif isUrlOrDomain(urlArg, urlRegex):
        urls.append(urlArg)
    else:
        invalidArgMessage = '''argument {} is neither a URL or a file, skipping this 
one'''
        logger.warn(invalidArgMessage.format(urlArg))
urls = list(set(urls)) # only unique URLs

# split into chunks to obey request size limits
chunks = [urls[x:x + CHUNKSIZE] for x in range(0, len(urls), CHUNKSIZE)]
logger.info('total URLs: {}. Split into {} chunks.'.format(len(urls), len(chunks)))

# send one API call per chunk
for chunkIndex, chunk in enumerate(chunks):
    logger.info('getting results for chunk {} of {}'.format(chunkIndex + 1, len(chunks)))
    # contains all listed threat types, platform types, and threat entry types
    body = {
            'client': {
                    'clientId': 'arceo',
                    'clientVersion': '0.1'
            },
            'threatInfo': {
                'threatTypes': ['THREAT_TYPE_UNSPECIFIED', 'MALWARE',
                                'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                                'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['THREAT_ENTRY_TYPE_UNSPECIFIED', 'URL',
                                     'EXECUTABLE'],
                'threatEntries': [{'url': url} for url in chunk]
            }
    }
    retryNumber = 0 # will retry up to five times on certain failures
    try:
        service = build('safeBrowsing', 'v4', developerKey = apiKey)
    except ServerNotFoundError:
        logger.error('''A network issue will not allow us to connect to Google.
Troubleshoot your connection then try again.''')
        quit()
    
    # recursive function for retries
    def executeAndPrintHttpRequest(httpRequest, retryNumber):
        try: pprint(httpRequest.execute())
        except HttpError as httpError:
            status = httpError.resp.status
            if status == 400:
                logger.error('Invalid argument (invalid request payload). ' + \
                      'Contact author of this script')
                quit()
            if status == 403:
                logger.error(' Permission denied (invalid API key/quota exceeded).')
                quit()
            elif status in [500, 503, 504]:
                if retryNumber < 5:
                    retryNumber += 1
                    logger.warn('HTTP error {}, retrying request... (retry #{})'.format(
                        status, retryNumber))
                    sleep(5)
                    executeAndPrintHttpRequest(httpRequest, retryNumber)
                else:
                    logger.error('max consecutive retries exceeded, quitting...')
                    quit()
    executeAndPrintHttpRequest(service.threatMatches().find(body = body),
                               retryNumber)