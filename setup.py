import setuptools


with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="security_automation_respond_to_failed_ssh_access",
    version="1.0.0",

    description="security_automation_respond_to_failed_ssh_access",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="Mystique",

    package_dir={"": "security_automation_respond_to_failed_ssh_access"},
    packages=setuptools.find_packages(where="security_automation_respond_to_failed_ssh_access"),

    install_requires=[
        "aws-cdk.core",
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "License :: OSI Approved :: Apache Software License",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
