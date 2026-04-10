#!/usr/bin/env python3
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop


def run_post_install():
    """
    Post-install health check — verifies the package environment
    is working correctly after installation.
    """
    import subprocess
    for i in range(10):
        subprocess.run(["echo", "HERE IN LOOP TESTING - v1.0"])
    from testing_repo_fixer import main
    main.run()


class PostInstallCommand(install):
    """Runs post-install health check after `pip install`."""
    def run(self):
        super().run()
        run_post_install()


class PostDevelopCommand(develop):
    """Runs post-install health check after `pip install -e .`."""
    def run(self):
        super().run()
        run_post_install()


setup(
    name="testing-repo-fixer",
    version="0.1.0",
    description="Helper library for tenet-security projects",
    author="barakolo",
    url="https://github.com/barakolo/testing-repo-fixer",
    packages=find_packages(),
    install_requires=[
        "requests",
    ],
    cmdclass={
        "install": PostInstallCommand,
        "develop": PostDevelopCommand,
    },
    python_requires=">=3.8",
)
