from distutils.core import setup
from distutils.extension import Extension

setup(name="AIEngine",
    ext_modules=[
        Extension("pyaiengine", ["py_wrapper.cc"],
        libraries = ["boost_python","liblog4cxx"])
    ])

