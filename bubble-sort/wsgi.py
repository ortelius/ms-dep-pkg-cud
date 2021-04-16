from flask import Flask  #  module to create an api 
from bubblesort import app


if __name__ == '__main__':

    app.run('127.0.0.1', 5000, debug=True)