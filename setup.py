from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="heimdall-sp-validator-sdk",  # Use hyphens for PyPI package name
    version="0.1.0",
    author="IAM Heimdall Team",
    author_email="contact@iamheimdall.com",
    description="Service Provider SDK for validating Agent Identity Framework (AIF) tokens",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/aif-sp-validator-sdk",
    project_urls={
        "Homepage": "https://poc.iamheimdall.com",
        "Documentation": "https://github.com/your-org/aif-sp-validator-sdk#readme",
        "Repository": "https://github.com/your-org/aif-sp-validator-sdk",
        "Issues": "https://github.com/your-org/aif-sp-validator-sdk/issues",
    },
    packages=find_packages(),
    install_requires=[
        "pydantic>=2.0.0,<3.0.0",
        "PyJWT[cryptography]>=2.8.0,<3.0.0",
        "httpx>=0.20.0,<1.0.0",
        "cryptography>=3.4.0,<42.0.0"
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-asyncio>=0.18.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
        "test": [
            "pytest>=6.0",
            "pytest-asyncio>=0.18.0",
            "httpx-mock>=0.7.0",
        ]
    },
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
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "Topic :: Security :: Cryptography",
    ],
    keywords="aif, agent, identity, framework, jwt, token, validation, security",
    python_requires=">=3.8",
    include_package_data=True,
    zip_safe=False,
)