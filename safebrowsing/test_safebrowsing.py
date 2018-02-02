from googleapiclient.errors import HttpError
from googleapiclient.http import HttpRequest
import json
import os
import safebrowsing
import tempfile
import unittest
from unittest.mock import patch, Mock, MagicMock


class TestSafebrowsing(unittest.TestCase):

    def test_isUrlOrDomain(self):
        self.assertTrue(safebrowsing.isUrlOrDomain('https://www.google.com/'))
        self.assertTrue(safebrowsing.isUrlOrDomain('google.com'))

    def test_addProtocol(self):
        self.assertEqual(
            safebrowsing.addProtocol('google.com', 'https'),
            'https://google.com')
        self.assertEqual(
            safebrowsing.addProtocol('google.com', 'http'),
            'http://google.com')
        self.assertEqual(
            safebrowsing.addProtocol('https://google.com', 'https'),
            'https://google.com')

    def test_getAPIKey(self):
        self.assertEqual(safebrowsing.getAPIKey('dummy'), -1)
        with tempfile.NamedTemporaryFile(mode='wb') as tempFile:
            tempFile.write(os.urandom(8))
            tempFile.seek(0)
            self.assertEqual(safebrowsing.getAPIKey(tempFile.name), -1)

    def test_getChunks(self):
        self.assertEqual(
            safebrowsing.getChunks(['google.com'] * 2),
            [['google.com'] * 2])
        self.assertEqual(
            safebrowsing.getChunks(['google.com'] * 1000),
            [['google.com'] * 500, ['google.com'] * 500])

    def test_getResults(self):
        self.assertEqual(
            safebrowsing.getResults(
                safebrowsing.getChunks(['google.com']),
                safebrowsing.getAPIKey()),
            [{}])
        self.assertEqual(
            safebrowsing.getResults(
                safebrowsing.getChunks(['google.com']),
                'badAPIkey'),
            [-1])

        def testBody(chunk):
            return 'test'
        self.assertEqual(
            safebrowsing.getResults(
                safebrowsing.getChunks(['google.com']),
                safebrowsing.getAPIKey(),
                testBody),
            [-1])

        class Resp:
            def __init__(self, status):
                self.status = status
                self.reason = 'just because'

        for errorNumber in [400, 403, 500, 503, 504]:
            dataDict = {'error': {
                'message': 'test message'
            }}
            content = json.dumps(dataDict).encode()
            error = HttpError(Resp(errorNumber), content)
            with patch.object(HttpRequest, 'execute') as mockHttpRequest:
                mockHttpRequest.side_effect = error
                self.assertEquals(
                    safebrowsing.getResults(
                        safebrowsing.getChunks(['google.com']),
                        safebrowsing.getAPIKey()),
                    [-1])

    def test_getListOfURLsFromFile(self):
        if os.name == 'nt':
            safebrowsing.logger.warning(
                'test_getListOfURLsFromFile will not run properly on Windows, '
                'skipping')
        else:
            urls = ['google.com', 'fourmajor.com']
            with tempfile.NamedTemporaryFile(mode='r+') as tempFile:
                for url in urls:
                    tempFile.write('{}\n'.format(url))
                tempFile.seek(0)
                self.assertEqual(
                    safebrowsing.getListOfURLsFromFile(tempFile.name), urls)
            with self.assertRaises(UnicodeDecodeError):
                with tempfile.NamedTemporaryFile(mode='wb') as tempFile:
                    tempFile.write(os.urandom(8))
                    tempFile.seek(0)
                    safebrowsing.getListOfURLsFromFile(tempFile.name)


if __name__ == '__main__':
    unittest.main()
