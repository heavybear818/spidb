from setuptools import setup, find_packages

setup(
    name="spidb",
    version="0.1.0",
    description="A simple wrapper library for securing passwords in databases",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Heavy Bear",
    author_email="heavybear818@gmail.com",
    url="https://github.com/heavybear818/spidb",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "cryptography>=44.0.0",
        "bcrypt>=4.0.0"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)
