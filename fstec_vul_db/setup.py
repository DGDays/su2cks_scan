from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip() for line in fh if line.strip() and not line.startswith("#")
    ]

setup(
    name="vuln-redis",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A Redis-based vulnerability database for Russian BDU FSTEC data",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    keywords="vulnerability, redis, security, bdu, fstec",
    url="https://github.com/yourusername/vuln-redis",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/vuln-redis/issues",
        "Source": "https://github.com/yourusername/vuln-redis",
    },
)
