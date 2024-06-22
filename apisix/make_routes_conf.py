import requests
import time
import json
# curl http://127.0.0.1:9180/apisix/admin/routes -H "X-API-KEY:edd1c9f034335f136f87ad84b625c8f1"
# curl -i -H "Content-Type: application/json" -H 'Cookie: customer_product_cookie=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhY2NvdW50X2FnZ3JlZ2F0b3IiLCJpc3MiOiJhY2NvdW50X2FnZ3JlZ2F0b3IgdG9rZW4gZ2VuZXJhdGlvbiIsImN1c3RvbWVyaWQiOiI0NTY3OCIsImV4cCI6MTcxOTA1NjM0N30.zLjrqMdJ5S8ZKqK0wNFHZJE3DMZgCehcMvF81mPs8Y8' http://127.0.0.1:9080/get-product/P1234
url = 'http://api_apache-apisix_1:9180/apisix/admin/routes'
headers = {"X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1"}

status = 0

print("::::::Starting Script")
time.sleep(20)
while (status != 200):
    try:
        response = requests.get(url = url,headers=headers)
        status = response.status_code
        response_json = response.json()
        print(response_json, status)
    except Exception as E:
        print(E)

print(":::::::::Adding login")
    
try:
    payload_arry = [
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
        },
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
        },
        {
            "id": "flask-api-get-product",
            "uri": "/get-product/*",
            "upstream": {
                "type": "roundrobin",
                "nodes": {
                "flask-cont:23002": 1,
                "flask-cont1:23002": 1
                }
            }
        } 
    ]
    for item in payload_arry:
        response = requests.put(url = url, headers=headers, data=json.dumps(item))
        print(response.json(), response.status_code)
except Exception as E:
    print(E)
    
print("::::::Ending Script")