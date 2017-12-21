# py-safebrowsing
A Python script which queries the Google Safe Browsing API

To use, first you will need an API key from Google as follows: https://support.google.com/cloud/answer/6158862?hl=en&ref_topic=6262490

Save your API key in a file called "google_api_key" in the working directory.

Then you can run run.py with any number of arguments. The arguments should be either URLs, domains, or files. URLs without the protocol are OK. Files should have one domain or URL per line with no other characters on that line.

There are usage limits for the API that you should familiarize yourself with.

The script returns one or more JSON responses. If you have many URLs you are checking, you may want to redirect output to a file.

A known limitation is the URL checking regular expression will not catch absolutely all valid URLs, for instance those including unicode characters.

This was developed using Python 3.6.1. Different versions of Python may have different results.

A future improvement could include direct writing of the output to a file. It could also include different output formats, or combining all the JSON responses into one output.
