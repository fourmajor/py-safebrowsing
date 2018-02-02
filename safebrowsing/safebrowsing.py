from apiclient.discovery import build
from googleapiclient.errors import HttpError
from httplib2 import ServerNotFoundError
import logging
import re
from time import sleep

logger = logging.getLogger('safeBrowsing')
logger.setLevel(logging.WARNING)
logger.addHandler(logging.StreamHandler())
APIFILENAME = '../google_api_key'

# "The HTTP POST request can include up to 500 URLs"
# https://developers.google.com/safe-browsing/v4/lookup-api
CHUNKSIZE = 500


def getListOfURLsFromFile(filename):
    urls = []
    try:
        with open(filename) as urlFile:
            try:
                for line in urlFile:
                    # should check if it can properly decode the file
                    # (text or binary?)
                    if line.startswith('#'):
                        continue
                    if isUrlOrDomain(line):
                        urls.append(line.strip())
                    else:
                        logger.warn(
                            'in file {}, {} is not a url, skipping'.format(
                                filename, line))
                return urls
            except UnicodeDecodeError:
                logger.error(
                    'file {} is not the correct format, cannot read some '
                    'or all of it as URLs'.format(filename))
                raise
    except IOError:
        logger.warn(
            '{} is a file but is not readable, skipping'.format(filename))


def getBody(chunk):
    return {
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


def getResults(chunks, apiKey, getBody=getBody):
    results = []

    # send one API call per chunk
    for chunkIndex, chunk in enumerate(chunks):
        logger.info('getting results for chunk {} of {}'.format(
            chunkIndex + 1, len(chunks)))
        # contains all listed threat types, platform types, and threat entry
        # types
        body = getBody(chunk)

        try:
            service = build('safeBrowsing', 'v4',
                            developerKey=apiKey)
        except ServerNotFoundError:
            logger.error(
                'A network issue will not allow us to connect to Google. '
                'Troubleshoot your connection then try again.')
            continue

        # recursive function for retries
        httpRequest = service.threatMatches().find(body=body)
        results.append(executeHttpRequest(httpRequest, 0))
    return results


def getChunks(urls):
    chunks = [urls[x:x + CHUNKSIZE] for x in range(0, len(urls), CHUNKSIZE)]
    logger.info(
        'total URLs: {}. Split into {} chunks.'.format(len(urls), len(chunks)))
    return chunks


def getAPIKey(apiKeyFile=APIFILENAME):
    # get the API key from file
    try:
        with open(apiKeyFile) as fh:
            return fh.read()
    except FileNotFoundError:
        logger.error(
            'You must include your Google API key in '
            'the file {}. To get a Google API key, follow these instructions: '
            'https://support.google.com/cloud/answer/6158862?hl=en&ref_topic=6'
            '262490'.format(apiKeyFile))
        return -1
    except IOError:
        logger.error('API key file {} not readable, quitting')
        return -1
    except UnicodeDecodeError:
        logger.error(
            'API key file has a unicode error. Is it the correct format? '
            'Quitting.')
        return -1


def addProtocol(url, protocol):
    # used to add protocol part to url
    if re.match('.+://.+', url):
        return url
    else:
        return '{}://{}'.format(protocol, url)


def isUrlOrDomain(url):
    # url matching regex from https://stackoverflow.com/a/6883094/6423354
    # this regex should be improved, for example to match unicode characters
    regex = re.compile(
        '^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-'
        '9a-fA-F]))+$', re.IGNORECASE)
    return regex.match(url) or regex.match(addProtocol(url, 'http')) or \
        regex.match(addProtocol(url, 'https'))


def executeHttpRequest(httpRequest, retryNumber):
    try:
        return httpRequest.execute()
    except HttpError as httpError:
        status = httpError.resp.status
        if status == 400:
            logger.error(
                'Invalid argument (invalid request payload). '
                'Contact author of this script')
            return -1
        elif status == 403:
            logger.error(
                ' Permission denied (invalid API key/quota exceeded).')
            return -1
        elif status in [500, 503, 504]:
            if retryNumber < 5:
                retryNumber += 1
                logger.warn(
                    'HTTP error {}, retrying request... (retry #{})'.format(
                        status, retryNumber))
                sleep(1)
                return executeHttpRequest(httpRequest, retryNumber)
            else:
                logger.error('max consecutive retries exceeded, quitting...')
                return -1
