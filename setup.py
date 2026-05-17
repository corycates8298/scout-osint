from setuptools import setup, find_packages

setup(
    name="scout-osint",
    version="2.0.0",
    description="Unified OSINT intelligence gathering CLI — 8 target types, 20+ tools, parallel execution",
    author="Cory Cates",
    author_email="corycates8298@gmail.com",
    url="https://github.com/corycates8298/scout-osint",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "holehe",
        "socialscan",
        "maigret",
        "theHarvester",
        "ghunt",
        "ignorant",
        "crosslinked",
        "h8mail",
        "python-whois",
        "ipwhois",
        "waybackpy",
        "builtwith",
        "webtech",
        "email-validator",
        "google-search-results",
    ],
    entry_points={
        "console_scripts": [
            "scout-osint=scout_osint.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
)
