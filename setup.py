# https://setuptools.readthedocs.io/
# https://docs.python.org/2/distutils/index.html
# https://docs.python.org/3/distutils/index.html
import setuptools
import versioneer

# https://docs.python.org/2/distutils/setupscript.html#additional-meta-data
# https://docs.python.org/3/distutils/setupscript.html#additional-meta-data
# https://setuptools.readthedocs.io/en/latest/setuptools.html#new-and-changed-setup-keywords
# https://setuptools.readthedocs.io/en/latest/setuptools.html#metadata

setuptools.setup(
    name="xadix-cloudflare",
    description="CLI for cloudflare api",
    url="https://github.com/xadix/cloudflare-api-py",
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    packages=setuptools.find_packages(),
    py_modules=[],
    entry_points={
        "console_scripts": [
            "xdx-cloudflare=xadix.cloudflare.cli:main",
        ]
    },
    install_requires=[
        "requests>=2.18.4",
        "tabulate>=0.8.2",
        "dnspython>=1.15.0",
        "cloudflare>=2.1.0",
    ],
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
    ],
    keywords='cloudflare',
    python_requires='>=2.7, <3',
)
