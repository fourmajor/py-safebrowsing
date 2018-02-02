from distutils.core import setup
from setuptools import find_packages

setup(name='py-safebrowsing',
      version='1.0.0',
      description='A Python module which queries the Google Safe Browsing API',
      url='https://github.com/fourmajor/py-safebrowsing',
      author='Stu Chuang Matthews',
      author_email='stu@fourmajor.com.',
      license='MIT',
      classifiers=[
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3.6'],
      packages=find_packages(),
      install_requires=[
          'argparse', 'apiclient', 'google-api-python-client', 'httplib2'],
      python_requires='>=3',
      package_data={'domains': ['domains.txt']})
