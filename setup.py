from setuptools import find_packages, setup


setup(
    name='Aberdeen',
    version='0.0.1',
    description='Test Snort rules and NIDS',
    license='LICENSE',
    packages=find_packages(exclude=['tests', 'configs']),
    data_files=[('configs', ['configs/file_magic.lua',
                             'configs/snort3.lua',
                             'configs/snort_defaults.lua']),
                ],
    include_package_data=True,
    install_requires=[
        'click~=8.0.3',
        'rstr~=3.1.0',
        'scapy~=2.4.5',
    ],
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
    ],
    entry_points={
        'console_scripts': [
            'aberdeen = aberdeen.app:cli_app',
        ],
    }
)
