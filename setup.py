from distutils.core import setup, Extension
from Cython.Build import cythonize

ext_modules = [
  Extension(
    name='wypcap',
    sources=['wypcap.pyx'],
    libraries=['wpcap', 'Packet'],
    library_dirs=['./npcap/Lib/x64'],
    include_dirs=['./npcap/Include']
  )
]

setup(ext_modules=cythonize(ext_modules))
