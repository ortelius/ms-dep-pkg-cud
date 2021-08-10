import os

import psycopg2
import pybreaker
from flask import Flask, request  # module to create an api
from flask_restful import Api, Resource

# Init Flask
app = Flask(__name__)
api = Api(app)

# Init db connection
db_host = os.getenv("DB_HOST", "localhost")
db_name = os.getenv("DB_NAME", "postgres")
db_user = os.getenv("DB_USER", "postgres")
db_pass = os.getenv("DB_PASS", "postgres")
db_port = os.getenv("DB_PORT", "5432") 

conn_circuit_breaker = pybreaker.CircuitBreaker(
    fail_max=1,
    reset_timeout=10,
)

@conn_circuit_breaker
def create_conn():
    conn = psycopg2.connect(host=db_host, database=db_name, user=db_user, password=db_pass, port=db_port)
    return conn

class Componentdeps(Resource):
    def post(self):
        conn = create_conn() 
        conn.set_session(autocommit=False)
        compid = request.args.get('compid', None)
        components_data = []
        component_json = request.get_json()

        deptype = component_json.get('bomFormat', None)

        # Parse CycloneDX BOM for licenses
        if (deptype is not None and deptype == 'CycloneDX'):
            components = component_json.get('components')
            deptype = 'license'
            for component in (components):
                packagename = component.get('name')
                packageversion = component.get('version','')
                license_url = ''
                license_name =  ''
                licenses = component.get('licenses')
                if (licenses):
                    license_name = licenses[0].get('license').get('name', '')
                    license_url = 'https://spdx.org/licenses/' + license_name + '.html'
                component_data = (compid, packagename, packageversion, deptype, license_name, license_url )
                components_data.append(component_data)

        try:
            print(components_data)
            cursor = conn.cursor()
            records_list_template = ','.join(['%s'] * len(components_data))

            #delete old licenses
            sql = 'DELETE from dm_componentdeps where compid=%s and deptype=%s'
            params=(compid, deptype,)
            cursor.execute(sql, params)

            #insert into database
            sql = 'INSERT INTO dm_componentdeps(compid, packagename, packageversion, deptype, name, url) VALUES {}'.format(records_list_template)

            cursor.execute(sql, components_data)

            rows_inserted = cursor.rowcount
            # Commit the changes to the database
            conn.commit()
            if rows_inserted > 0:
                return ({"message": 'components updated Succesfully'})

            return ({"message": 'oops!, Something went wrong!'})

        except Exception as e:
            print(e)
            cursor = conn.cursor()
            cursor.execute("ROLLBACK")
            conn.commit() 

            return ({"message": 'oops!, Something went wrong!'})
            

    def delete(self):
        compid = request.args.get('compid', -1)
        deptype = request.args.get('deptype', None)

        try:
            conn = create_conn() 
            cursor = conn.cursor()

            #delete into database
            sql = 'DELETE from dm_componentdeps where compid=%s and deptype=%s'

            params=(compid, deptype,)
            cursor.execute(sql, params)

            rows_inserted = cursor.rowcount
            # Commit the changes to the database
            conn.commit()
            if rows_inserted > 0:
                return ({"message": f'compid {compid} deleted'})
            
            return ({"message": f'Something went wrong!, Couldn\'t delete comp id {compid}'})

        except Exception as e:
            print(e)
            cursor = conn.cursor()
            cursor.execute("ROLLBACK")
            conn.commit() 

            return ({"message": f'Something went wrong!, Couldn\'t delete comp id {compid}'})

api.add_resource(Componentdeps, '/msapi/deppkg')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5003)
