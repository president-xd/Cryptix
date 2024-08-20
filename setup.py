from setuptools import setup, find_packages

setup(
    name='Cryptix',
    version='0.1.0',
    description='A versatile cryptography library ' \
    'for various encryption and decryption techniques.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Mohsin Mukhtiar Lashari Baloch',
    author_email='lasharimohsin19@gmail.com',
    url='https://github.com/president-xd/Cryptix',
    packages=find_packages(),
    install_requires=[
        'numpy',
        'cryptography'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography'
    ],
    python_requires='>=3.6',
    include_package_data=True,
    package_data={
        '': ['LICENSE', 'MANIFEST.in', 'README.md']
    },
    entry_points={
        'console_scripts': [],
    }
)
