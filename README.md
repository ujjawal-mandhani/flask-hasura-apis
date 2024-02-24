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