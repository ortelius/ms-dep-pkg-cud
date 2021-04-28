# ortelius-ms-dep-pkg-cud

Dependency Package Data Microservice - Create, Update and Delete

HELM_CHART

    - port:8080

    - package name : deppkg

postgress test database docker image - [https://github.com/ortelius/test-database]
Pull and run the above image

Create Table Componentdeps with  [https://github.com/ortelius/ortelius/blob/main/dmadminweb/WebContent/WEB-INF/schema/2021041701].sql SQl query.

Microservice

    - url : localhost:5000/msapi/deppkg
  methods:
  
    -POST 
        sample call : 
        
           - curl -X POST - -H "Content-Type: application/json" -d @FILENAME DESTINATION http://localhost:5000/msapi/deppkg



    -DELETE 
        #deletes component by component id passed as query Parameter
        
        sample call : 
        
        - curl -X DELETE localhost:5000/msapi/compitem?comp_id=1
