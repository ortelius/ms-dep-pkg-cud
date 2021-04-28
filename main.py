
from flask import Flask , request #  module to create an api 
import json # module to parse json data
from flask_restful import Api, Resource
import psycopg2
import os

# Init Flask
app = Flask(__name__)
api = Api(app)

# Init db connection
db_host = os.getenv("DB_HOST", "localhost")
db_name = os.getenv("DB_NAME", "postgres")
db_user = os.getenv("DB_USER", "postgres")
db_pass = os.getenv("DB_PASS", "postgres")
db_port = os.getenv("DB_PORT", "5432") 


conn = psycopg2.connect(host=db_host, database=db_name, user=db_user, password=db_pass, port=db_port)


class Componentdeps(Resource):
    def post(self):
        components_data = []
        component_json = request.get_json()
        components = component_json.get('components')
        for i, component in enumerate(components):
            packagename = component.get('name')
            packageversion = component.get('version','')
            cve = ''
            cve_url = component.get('purl', '')
            licenses = component.get('licenses')
            if licenses == []:
                license =  ''
            else:   
                license= licenses[0].get('license').get('name')
            license_url = ''
            component_data = (i+1,packagename, packageversion,cve, cve_url ,license ,license_url )
            
            components_data.append(component_data)

        try:
            print(components_data)
            cursor = conn.cursor()
            records_list_template = ','.join(['%s'] * len(components_data))

            #insert into database
            sql = 'INSERT INTO dm_componentdeps(compid,packagename, packageversion, cve, cve_url, license, license_url) \
                VALUES {}'.format(records_list_template)
                

            cursor.execute(sql, components_data)

            rows_inserted = cursor.rowcount
            # Commit the changes to the database
            conn.commit()
            if rows_inserted > 0:
                return ({"message": f'components updated Succesfully'})
            else:
                return ({"message": f'oops!, Something went wrong!'})

        except Exception as e:
            print(e)
            cursor = conn.cursor()
            cursor.execute("ROLLBACK")
            conn.commit() 

            return ({"message": f'oops!, Something went wrong!'})
            

    def delete(self):
        compid = request.args.get('comp_id')

        try:
            cursor = conn.cursor()

            #delete into database
            sql = 'DELETE from dm_componentdeps where compid= {}'.format(compid)

            cursor.execute(sql)

            rows_inserted = cursor.rowcount
            # Commit the changes to the database
            conn.commit()
            if rows_inserted > 0:
                return ({"message": f'comp id {compid} deleted'})
            else:
                return ({"message": f'Something went wrong!, Couldn\'t delete comp id {compid}'})

        except Exception as e:
            print(e)
            cursor = conn.cursor()
            cursor.execute("ROLLBACK")
            conn.commit() 

            return ({"message": f'Something went wrong!, Couldn\'t delete comp id {compid}'})
            


api.add_resource(Componentdeps, '/msapi/deppkg')






# def bubble_sort(array):
#     '''
#     A function to sort a list using the bubble sort method

#     Args:
#      array - (list) A list of integers or float 

#     Returns:
#      array - (list) A sorted list      
#     '''
#     # get length of array
#     n = len(array)
    
#     #loop through the list and compare the values
#     for i in range(n-1):
#         for j in range(n-1-i):
#             if array[j]> array[j+1]:

#                 #swap values
#                 array[j], array[j+1] = array[j+1], array[j]
#     return array




# @app.route('/msapi/deppkg', methods = ['POST'])
# def index():
#     '''
#     A flask function that sorts an a list and return json data 
    
#     '''
#     array = [10, 1, 200, -19, 21, 321, 0, 200 ]

#     # sort the array list using the bubble sort function
#     sorted_array = bubble_sort(array)
#     return json.dumps(sorted_array)





