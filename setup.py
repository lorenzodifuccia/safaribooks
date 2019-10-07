from setuptools import setup, find_packages

setup(
    name='safaribooks',
    version='0.1.0',
    description='Download and generate EPUB of your favorite books from Safari Books Online library.',
    author='Lorenzo Di Fuccia',
    author_email='lorenzo.difuccia@gmail.com',
    url='https://github.com/lorenzodifuccia/safaribooks.git',
    packages=find_packages(),
    entry_points={
        'console_scripts': 'safaribooks=safaribooks.safaribooks:run'
    },
    install_requires=[
        'lxml>=4.1.1',
        'requests>=2.20.0'
    ]
)