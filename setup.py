from setuptools import setup, find_packages

setup(
    name="vumi-http-api",
    version="0.1.2a",
    url='http://github.com/praekelt/vumi-http-api',
    license='BSD',
    description="An HTTP API for interacting with vumi",
    long_description=open('README.md', 'r').read(),
    author='Praekelt Foundation',
    author_email='dev@praekeltfoundation.org',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'vumi',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
