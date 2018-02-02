from run import main
import io
import os
import sys
import tempfile
import unittest


class TestRun(unittest.TestCase):

    def test_main(self):
        if os.name == 'nt':
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput
            main(['google.com', 'notafileorurl'])
            self.assertEqual(capturedOutput.getvalue(), '{}\n')
        else:
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput
            with tempfile.NamedTemporaryFile(mode='r+') as tempFile:
                tempFile.write('wikipedia.org\n')
                main(['google.com', tempFile.name, 'notafileorurl'])
            self.assertEqual(capturedOutput.getvalue(), '{}\n')
        self.assertEqual(
            main(['google.com'], 'badfilename'),
            -1)


if __name__ == '__main__':
    unittest.main()
