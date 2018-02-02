from argparse import ArgumentParser
from os.path import exists
from pprint import pprint
import safebrowsing
import sys


def main(urlArgs, apiFile=safebrowsing.APIFILENAME):
    apiKey = safebrowsing.getAPIKey(apiFile)
    if apiKey == -1:
        print('bad api key')
        return -1

    urls = []
    for urlArg in urlArgs:
        # argument from command line is a file
        if exists(urlArg):
            urls += safebrowsing.getListOfURLsFromFile(urlArg)
        # if it's not a file, is the argument a URL?
        elif safebrowsing.isUrlOrDomain(urlArg):
            urls.append(urlArg)
        else:
            safebrowsing.logger.warn('argument {} is neither a URL or a file, '
                                     'skipping this one'.format(urlArg))
    urls = list(set(urls))  # only unique URLs

    # split into chunks to obey request size limits
    chunks = safebrowsing.getChunks(urls)

    results = safebrowsing.getResults(chunks, apiKey)

    # print results
    for result in results:
        if result == -1:
            return -1
        else:
            pprint(result)
    return 0


if __name__ == '__main__':
    # process input
    parser = ArgumentParser(
        description='Check URLs against the Google Safe Browsing API')
    parser.add_argument('url', nargs='+',
                        help='domain, url, or file containing one of the '
                        'former')
    args = parser.parse_args()
    urlArgs = list(set(args.url))  # only unique args
    sys.exit(main(urlArgs))
