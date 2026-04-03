from setuptools import setup, find_packages

setup(
    name="keyshield",
    version="3.0.0",
    description="All-in-One Input Security Monitor with Web GUI",
    author="KeyShield Project",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "psutil>=5.9.0",
        "flask>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "keyshield=keyshield.cli.main:main",
        ],
    },
    package_data={
        "keyshield": [
            "web/templates/*.html",
            "web/static/css/*.css",
            "web/static/js/*.js",
            "web/static/img/*.svg",
        ],
    },
)
