### Flask Hasura Apis

#### Urls

Hasura url = [Hasura-url](http://0.0.0.0:23003/console)

Elastic Search Url = [Elastic Search URL](http://0.0.0.0:9200/)

Elastic Search index count Url = [Elastic Search index count URL](http://0.0.0.0:9200/2024/_count)

Kibana Url = [Kibana Url](http://0.0.0.0:5601/)

#### Requirements

docker and docker-compose

```bash
docker-compose build 
docker-compose up -d
```

#### Required Relationships in Hasura

![Relationship - 1](src/images/relation1.png)


![Relationship - 2](src/images/relationship2.png)


![Relationship - 3](src/images/relation3.png)


#### ElasticSearch 

Elastic Search Url

![Elastic Search Url](src/elastic_search_url.png)

Elastic Index Count Url

![Elastic Search Url](src/elasticsearch_index_count.png)

Elastic Search Health 

![Elastic_search_health](src/Elastic_search_health.png)

#### Kibana 

Home Page 

![Kibana_home_page](src/Kibana_home_page.png)

**Logs Page**

You need to create search pattern for 2024

![kibana logs page](src/logs_page_kibana.png)


### Flask Cont2 

Flask Cont2 is created because Testing of APISIX integration

#### Example from Docs

```bash

curl -i "http://0.0.0.0:9180/apisix/admin/routes" -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
  "id": "getting-started-ip",
  "uri": "/ip",
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "httpbin.org:80": 1
    }
  }
}'```

```bash 
curl http://0.0.0.0:9080/ip

```
#### Example from Login using api gateway apisix 


```bash
curl -i "http://0.0.0.0:9180/apisix/admin/routes" -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
  "id": "flask-apis-login-customer",
  "uris": ["/login", "/login/"],
  "vars": [
    ["http_content_type", "==", "application/json"]
  ],
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "flask-cont:23002": 1,
      "flask-cont1:23002": 1
    }
  }
}'```

```bash
curl --location '0.0.0.0:9080/login/' \
--header 'Cookie: customer_product_cookie=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhY2NvdW50X2FnZ3JlZ2F0b3IiLCJpc3MiOiJhY2NvdW50X2FnZ3JlZ2F0b3IgdG9rZW4gZ2VuZXJhdGlvbiIsImN1c3RvbWVyaWQiOiI0NTY3OCIsImV4cCI6MTcxODkyMDMzN30.kmD3GYfbJpT_mU9wR-6uneTKXRr501jtwiWUz4NFA6U' \
--header 'Content-Type: application/json' \
--data '{
    "customerid":bash "45678",
    "password": "ujjawalpassword"
}'```

#### Example from get all products using api gateway apisix

```bash

curl -i "http://0.0.0.0:9180/apisix/admin/routes" -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
  "id": "flask-apis-get-all-products",
  "uris": ["/get-all-products", "/get-all-products/"],
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "flask-cont:23002": 1,
      "flask-cont1:23002": 1
    }
  }
}'```

```bash 
curl --location '0.0.0.0:9080/get-all-products' \
--header 'Cookie: customer_product_cookie=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhY2NvdW50X2FnZ3JlZ2F0b3IiLCJpc3MiOiJhY2NvdW50X2FnZ3JlZ2F0b3IgdG9rZW4gZ2VuZXJhdGlvbiIsImN1c3RvbWVyaWQiOiI0NTY3OCIsImV4cCI6MTcxODkyMDMzN30.kmD3GYfbJpT_mU9wR-6uneTKXRr501jtwiWUz4NFA6U'
```
