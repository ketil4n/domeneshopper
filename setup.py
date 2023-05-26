import setuptools

if __name__ == "__main__":
    setuptools.setup(name="domeneshopper",
                     version='0.3',
                     description='Create new subdomains on domeneshop.no',
                     author='Ketil Nordstad',
                     packages=['domeneshopper'],
                     package_data={'': ['*.htpl']},
                     install_requires=['domeneshop', 'python-dotenv'],
                     author_email='ketilkn@gmail.com',
                     scripts=['scripts/domeneshopper'])
