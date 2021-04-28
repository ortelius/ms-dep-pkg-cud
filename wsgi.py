from flask import Flask  #  module to create an api 
from main import app


if __name__ == '__main__':

    app.run('127.0.0.1', 5000, debug=True)