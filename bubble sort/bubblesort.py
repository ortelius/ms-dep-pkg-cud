
from flask import Flask  #  module to create an api 
import json # module to parse json data


app = Flask(__name__)


def bubble_sort(array):
    '''
    A function to sort a list using the bubble sort method

    Args:
     array - (list) A list of integers or float 

    Returns:
     array - (list) A sorted list      
    '''
    # get length of array
    n = len(array)
    
    #loop through the list and compare the values
    for i in range(n-1):
        for j in range(n-1-i):
            if array[j]> array[j+1]:

                #swap values
                array[j], array[j+1] = array[j+1], array[j]
    return array




@app.route('/', methods = ['POST', 'GET'])
def index():
    '''
    A flask function that sorts an a list and return json data 
    
    '''
    array = [10, 1, 200, -19, 21, 321, 0, 200 ]

    # sort the array list using the bubble sort function
    sorted_array = bubble_sort(array)
    return json.dumps(sorted_array)




if __name__ == '__main__':

    app.run()


