from setuptools import setup, find_packages

setup(
    name="cvesweep",
    version="1.0.0",
    description="Network CVE scanner — scans for open ports and maps service versions to known CVEs",
    author="WGilesCyber",
    license="MIT",
    packages=find_packages(),
    package_data={"cvesweep": ["templates/*.j2"]},
    python_requires=">=3.10",
    install_requires=[
        "python-libnmap>=0.7.3",
        "requests>=2.32.3",
        "rich>=13.9.4",
        "Jinja2>=3.1.6",
        "packaging>=25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "pytest-mock>=3.14",
            "responses>=0.25",
        ]
    },
    entry_points={
        "console_scripts": [
            "cvesweep=cvesweep.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Topic :: Security",
    ],
)
