import json
import os
import psycopg2
import pybreaker
import requests
import sqlalchemy.pool as pool
from flask import Flask, request
from flask_restful import Api, Resource
from werkzeug.utils import send_from_directory
from flask_swagger_ui import get_swaggerui_blueprint
from http import HTTPStatus
from webargs import fields, validate
from webargs.flaskparser import parser, abort

# Init Flask
app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static',path)

# swagger config
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.yml'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "ortelius-ms-dep-pkg-cud"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

# Init db connection
db_host = os.getenv("DB_HOST", "localhost")
db_name = os.getenv("DB_NAME", "postgres")
db_user = os.getenv("DB_USER", "postgres")
db_pass = os.getenv("DB_PASS", "postgres")
db_port = os.getenv("DB_PORT", "5432") 
validateuser_url = os.getenv("VALIDATEUSER_URL", "http://localhost:5000")

url = requests.get('https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json')
safety_db = json.loads(url.text)

# connection pool config
conn_pool_size = os.getenv("POOL_SIZE", 3)
conn_pool_max_overflow = os.getenv("POOL_MAX_OVERFLOW", 2)
conn_pool_timeout = os.getenv("POOL_TIMEOUT", 30.0) 

conn_circuit_breaker = pybreaker.CircuitBreaker(
    fail_max=1,
    reset_timeout=10,
)

@conn_circuit_breaker
def create_conn():
    conn = psycopg2.connect(host=db_host, database=db_name, user=db_user, password=db_pass, port=db_port)
    return conn

# connection pool init
mypool = pool.QueuePool(create_conn, max_overflow=conn_pool_max_overflow, pool_size=conn_pool_size, timeout=conn_pool_timeout)

# health check endpoint
class HealthCheck(Resource):
    def get(self):
        try:
            conn = mypool.connect() 
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            conn.close()
            if cursor.rowcount > 0:
                return ({"status": 'UP',"service_name": 'ortelius-ms-dep-pkg-cud'}),HTTPStatus.OK
            return ({"status": 'DOWN'}),HTTPStatus.SERVICE_UNAVAILABLE

        except Exception as e:
            print(e)
            return ({"status": 'DOWN'}),HTTPStatus.SERVICE_UNAVAILABLE

api.add_resource(HealthCheck, '/health')

class Componentdeps(Resource):
    def post(self):
        result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies)
        if (result is None):
            return None, 404

        if (result.status_code != 200):
            return result.json(), 404
        
        query_args_validations = {
            "compid": fields.Int(required=True, validate=validate.Range(min=1)),
        }

        parser.parse(query_args_validations, request, location="query")

        compid = request.args.get('compid', None)
        deptype = request.args.get('bomformat', None)
        components_data = []
        component_json = request.get_json()

        # Parse CycloneDX BOM for licenses
        if (deptype is not None and deptype.lower() == 'CycloneDX'.lower()):
            components = component_json.get('components')
            deptype = 'license'
            for component in (components):
                packagename = component.get('name')
                packageversion = component.get('version','')
                summary = ''
                license_url = ''
                license_name =  ''
                licenses = component.get('licenses')
                if (licenses):
                    license_name = licenses[0].get('license').get('name', '')
                    license_url = 'https://spdx.org/licenses/' + license_name + '.html'
                component_data = (compid, packagename, packageversion, deptype, license_name, license_url, summary )
                components_data.append(component_data)

        # Parse Python Safety for CVEs
        if (deptype is not None and deptype.lower() == 'safety'.lower()):
            deptype = 'cve'
            for component in (component_json):
                packagename = component[0] # name 
                packageversion = component[2] # version
                summary = component[3]
                safety_id = component[4] # cve id
                cve_url = ''
                cve_name = safety_id
                cve_detail = safety_db.get(packagename, None)
                if (cve_detail is not None):
                    for cve in cve_detail:
                        if (cve['id'] == 'pyup.io-' + safety_id):
                            cve_name = cve['cve']
                            if (cve_name.startswith('CVE')):
                                cve_url = 'https://nvd.nist.gov/vuln/detail/' + cve_name
                            break

                component_data = (compid, packagename, packageversion, deptype, cve_name, cve_url, summary )
                components_data.append(component_data)

        try:
            print("Components Data :",components_data)
            if len(components_data)==0:
                return ({"message": 'components not updated'}),HTTPStatus.OK

            conn = mypool.connect() 
            conn.set_session(autocommit=False)
            cursor = conn.cursor()
            records_list_template = ','.join(['%s'] * len(components_data))

            # delete old licenses
            sql = 'DELETE from dm_componentdeps where compid=%s and deptype=%s'
            params=(compid, deptype,)
            cursor.execute(sql, params)

            #insert into database
            sql = 'INSERT INTO dm_componentdeps(compid, packagename, packageversion, deptype, name, url, summary) VALUES {}'.format(records_list_template)

            cursor.execute(sql, components_data)

            rows_inserted = cursor.rowcount
            # Commit the changes to the database
            conn.commit()
            conn.close()
            if rows_inserted > 0:
                return ({"message": 'components updated succesfully'}),HTTPStatus.CREATED

            return ({"message": 'components not updated'}),HTTPStatus.OK

        except Exception as e:
            print(e)
            cursor = conn.cursor()
            cursor.execute("ROLLBACK")
            conn.commit()
            conn.close() 

            return ({"message": 'oops!, Something went wrong!'}),HTTPStatus.INTERNAL_SERVER_ERROR
            
    
    def delete(self):
        result = requests.get(validateuser_url + "/msapi/validateuser", cookies=request.cookies)
        if (result is None):
            return None, 404

        if (result.status_code != 200):
            return result.json(), 404

        query_args_validations = {
            "compid": fields.Int(required=True, validate=validate.Range(min=1)),
            "deptype": fields.Str(required=True, validate=validate.Length(min=1)),
        }

        parser.parse(query_args_validations, request, location="query")

        compid = request.args.get('compid', -1)
        deptype = request.args.get('deptype', None)

        try:
            conn = mypool.connect() 
            cursor = conn.cursor()

            # delete from database
            sql = 'DELETE from dm_componentdeps where compid=%s and deptype=%s'

            params=(compid, deptype,)
            cursor.execute(sql, params)

            rows_inserted = cursor.rowcount
            # Commit the changes to the database
            conn.commit()
            conn.close()
            if rows_inserted > 0:
                return ({"message": f'compid {compid} deleted'}),HTTPStatus.OK
            
            return ({"message": f'Something went wrong!, Couldn\'t delete comp id {compid}'}),HTTPStatus.OK

        except Exception as e:
            print(e)
            cursor = conn.cursor()
            cursor.execute("ROLLBACK")
            conn.commit()
            conn.close() 

            return ({"message": 'oops!, Something went wrong!'}),HTTPStatus.INTERNAL_SERVER_ERROR

api.add_resource(Componentdeps, '/msapi/deppkg')

# error handler for request validation errors
@parser.error_handler
def handle_request_parsing_error(err, req, schema, *, error_status_code, error_headers):
    abort(HTTPStatus.BAD_REQUEST,errors=err.messages)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5003)
