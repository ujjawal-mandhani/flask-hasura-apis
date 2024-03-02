import re
import json
import logging
import datetime
from flask import Flask, jsonify, make_response, request
import requests
import os
import sys
import uuid
from elasticsearch import Elasticsearch
from utils_folder.utils import hasura_api_key, hasura_api_value, secret_value_jwt, url, headers, verify_cookie_token, hash_password_func, verify_password, generateJWTToken, verifyJWTToken, update_headers

app = Flask(__name__)

es = Elasticsearch(['http://elasticsearch-cont:9200'])
class ElasticsearchHandler(logging.Handler):
    def emit(self, record):
        log_entry = {
            "@timestamp": datetime.datetime.utcnow().isoformat(),
            "log_level": record.levelname,
            "message": record.getMessage()
        }
        es.index(index='2024', body=log_entry)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = ElasticsearchHandler()
logger.addHandler(handler)

app.logger.setLevel(logging.INFO)
flask_handler = ElasticsearchHandler()
app.logger.addHandler(flask_handler)

# do not edit this global variable anywhere in code assign a new variable
query = """
{ 
  "query": "query MyQuery { customer_data ($variable$) { address1 address2 address3 adhar city country customerid dob email gender isadmin mobile name pan phone pincode state customer_product_details { customerid payment_amount payment_mode payment_timestamp productid productstatus } } product_customer_relation($variable$, distinct_on: productid) { product_details { payment_frequency product_pricing productid productname } } }",
  "variables":{}
}
"""

@app.route('/get-all-products', methods=['GET'])
def get_all_products():
  cookies = request.cookies
  response_verification, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification), resposne_code))
  payload = '{"query":"query MyQuery { product_attributes {payment_frequency product_pricing productid productname unique_identifier updated_timestamp } }","variables":{}}'
  response = requests.request("POST", url, headers=headers, data=payload)
  flask_response = update_headers(make_response(jsonify(response.json()), 200))
  return flask_response

@app.route('/get-product/<string:productid>', methods=['GET'])
def get_product(productid):
  cookies = request.cookies
  response_verification, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification), resposne_code))
  payload = '{"query":"query MyQuery { product_attributes(where: {productid: {_eq: \\"$productid$\\"}}) { payment_frequency product_pricing productid productname unique_identifier updated_timestamp } }","variables":{}}'.replace('$productid$', productid)
  app.logger.info(payload)
  response = requests.request("POST", url, headers=headers, data=payload)
  flask_response = update_headers(make_response(jsonify(response.json()), 200))
  return flask_response

@app.route('/delete-customer-details/<string:customerid>', methods=['DELETE'])
def delete_customer_details(customerid):
  cookies = request.cookies
  response_verification, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification), resposne_code))
  new_query = """
    {
      "query": "mutation MyMutation { delete_customer_password_details(where: {customerid: {_eq: \\"$customerid$\\"}}) { affected_rows } delete_product_customer_relation(where: {customerid: {_eq: \\"$customerid$\\"}}) { affected_rows } delete_customer_data(where: {customerid: {_eq: \\"$customerid$\\"}}) { affected_rows } }"
    }
  """
  new_query = new_query.replace('$customerid$', customerid)
  response = requests.request("POST", url, headers=headers, data=new_query).json()
  if response["data"]["delete_customer_data"]["affected_rows"] + response["data"]["delete_product_customer_relation"]["affected_rows"] + response["data"]["delete_customer_password_details"]["affected_rows"] != 3:
    flask_response = update_headers(make_response(jsonify({
        "message": "This customer id does not exist"
    }), 404))
    return flask_response
  flask_response = update_headers(make_response(jsonify({
      "message": "profile deleted successfully"
    }), 200))
  return flask_response

@app.route('/get-customer-details/<string:customerid>', methods=['GET'])
def get_customer_details(customerid):
  cookies = request.cookies
  response_verification, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification), resposne_code))
  global query
  new_query = query
  payload = 'where: {customerid: {_eq: \\"$customerid$\\"}}'.replace('$customerid$', customerid)
  new_query = new_query.replace('$variable$', payload)
  response = requests.request("POST", url, headers=headers, data=new_query)
  flask_response = update_headers(make_response(jsonify(response.json()), 200))
  return flask_response

@app.route('/update-password/', methods=['POST'])
def update_password():
  password_data = request.json
  cookies = request.cookies
  if password_data.get("old_password") in ["", None]:
    flask_response = update_headers(make_response(jsonify({
      "message": "old_password should not be empty"
    }), 400))
    return flask_response
  if password_data.get("new_password") in ["", None]:
    flask_response = update_headers(make_response(jsonify({
      "message": "new_password should not be empty"
    }), 400))
    return flask_response
  old_password = password_data.get("old_password") 
  new_password = password_data.get("new_password") 
  response_verification_or_customerid, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification_or_customerid), resposne_code))
  customerid = response_verification_or_customerid
  app.logger.info(customerid)
  payload_query = """{
      "query": "query MyQuery {customer_password_details($variable$) {    customerid    password  }}",
      "variables": {}
    }"""
  payload_variable = 'where: {customerid: {_eq: \\"$customerid$\\"}}'.replace('$customerid$', customerid)
  payload_query = payload_query.replace('$variable$', payload_variable)
  response = requests.request("POST", url, headers=headers, data=payload_query)
  app.logger.info(payload_query)
  password_details = response.json()
  if password_details["data"]["customer_password_details"] == []:
    flask_response = update_headers(make_response(jsonify({
      "message": "No data found for given customerid"
    }), 404))
    return flask_response
  hashed_password = password_details["data"]["customer_password_details"][0]["password"]
  is_password_correct = verify_password(old_password, hashed_password)
  if is_password_correct:
    password_update_query = """
      {
        "query":"mutation MyMutation {  update_customer_password_details($variable$) {    returning {      customerid      password    }  }}" 
      }
    """
    password_update_payload = 'where: {customerid: {_eq: \\"$customerid$\\"}}, _set: {password: \\"$new_hashed_password$\\", unique_identifier: \\"$unique_identifier$\\", updated_timestamp: \\"$updated_timestamp$\\"}'\
      .replace('$customerid$', customerid).replace('$new_hashed_password$', hash_password_func(new_password)).replace('$unique_identifier$', str(uuid.uuid4())).replace('$updated_timestamp$', str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')))
    password_update_query = password_update_query.replace('$variable$', password_update_payload)
    response_password_updated = requests.request("POST", url, headers=headers, data=password_update_query).json()
    if response_password_updated["data"]["update_customer_password_details"]["returning"] == []:
      flask_response = update_headers(make_response(jsonify({
        "message": "Something went wrong"
      }), 500))
    flask_response = update_headers(make_response(jsonify({
        "message": "Password updated successfully"
      }), 200))
  else:
    flask_response = update_headers(make_response(jsonify({
          "message": "old password is incorrect"
        }), 400))
  return flask_response


@app.route('/get-customer-mobile-details/<string:mobile>', methods=['GET'])
def get_customer_mobile_details(mobile):
  cookies = request.cookies
  response_verification, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification), resposne_code))
  global query
  new_query = query
  mobile_new  = mobile[-10:]
  get_customer_id_query = """
    { 
      "query": "query MyQuery { customer_data($variable$) { customerid } }",
      "variables":{}
    }
  """
  payload = 'where: {_or: [ { mobile: {_eq: \\"$mobile$\\"} }, { phone: {_eq: \\"$mobile$\\"} } ]}'.replace('$mobile$', mobile_new)
  get_customer_id_query = get_customer_id_query.replace('$variable$', payload)
  app.logger.info(get_customer_id_query)
  response_customerid = requests.request("POST", url, headers=headers, data=get_customer_id_query).json()
  app.logger.info(response_customerid)
  if response_customerid.get("data").get("customer_data") == []:
    flask_response = update_headers(make_response(jsonify({
      "message": "No data found for given mobile or phone"
    }), 200))
    return flask_response
  customerid = response_customerid.get("data").get("customer_data")[0]["customerid"]
  payload = 'where: {customerid: {_eq: \\"$customerid$\\"}}'.replace('$customerid$', customerid)
  new_query = new_query.replace('$variable$', payload)
  response = requests.request("POST", url, headers=headers, data=new_query)
  flask_response = update_headers(make_response(jsonify(response.json()), 200))
  return flask_response

@app.route('/get-customer-email-details/<string:email>', methods=['GET'])
def get_customer_email_details(email):
  email_new  = email.upper()
  cookies = request.cookies
  response_verification, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification), resposne_code))
  global query
  new_query = query
  get_customer_id_query = """
    { 
      "query": "query MyQuery { customer_data($variable$) { customerid } }",
      "variables":{}
    }
  """
  payload = 'where: {email: {_ilike: \\"$email$\\"}}'.replace('$email$', email_new)
  get_customer_id_query = get_customer_id_query.replace('$variable$', payload)
  app.logger.info(get_customer_id_query)
  response_customerid = requests.request("POST", url, headers=headers, data=get_customer_id_query).json()
  app.logger.info(response_customerid)
  if response_customerid.get("data").get("customer_data") == []:
    flask_response = update_headers(make_response(jsonify({
      "message": "No data found for given Email"
    }), 200))
    return flask_response
  customerid = response_customerid.get("data").get("customer_data")[0]["customerid"]
  payload = 'where: {customerid: {_eq: \\"$customerid$\\"}}'.replace('$customerid$', customerid)
  new_query = new_query.replace('$variable$', payload)
  response = requests.request("POST", url, headers=headers, data=new_query)
  flask_response = update_headers(make_response(jsonify(response.json()), 200))
  return flask_response

@app.route('/login/', methods=['POST'])
def login():
  login_data = request.json
  if login_data.get("password") in ["", None]:
    flask_response = update_headers(make_response(jsonify({
      "message": "password should not be empty"
    }), 400))
    return flask_response
  else:
    password = login_data["password"]
    if login_data.get("customerid") not in ["", None]:
      customerid = login_data.get("customerid")
      payload_query = """{
        "query": "query MyQuery {customer_password_details($variable$) {    customerid    password  }}",
        "variables": {}
      }"""
      payload_variable = 'where: {customerid: {_eq: \\"$customerid$\\"}}'.replace('$customerid$', customerid)
      payload_query = payload_query.replace('$variable$', payload_variable)
      response = requests.request("POST", url, headers=headers, data=payload_query)
      app.logger.info(payload_query)
      password_details = response.json()
      if password_details["data"]["customer_password_details"] == []:
        flask_response = update_headers(make_response(jsonify({
          "message": "No data found for given customerid"
        }), 404))
        return flask_response
      hashed_password = password_details["data"]["customer_password_details"][0]["password"]
      is_password_correct = verify_password(password, hashed_password)
      if is_password_correct:
        flask_response = update_headers(make_response(jsonify({
          "message": "password is correct"
        }), 200))
        expiration_time = datetime.datetime.now() + datetime.timedelta(days=1)
        flask_response.set_cookie('customer_product_cookie', generateJWTToken(customerid), expires=expiration_time)
      else:
        flask_response = update_headers(make_response(jsonify({
          "message": "password is incorrect"
        }), 400))
      return flask_response

    elif login_data.get("email") not in ["", None]:
      email = login_data.get("email")
      email_new  = email.upper()
      payload_password_email_query = """
        {
          "query": "query MyQuery { customer_data($variable$) { customer_password_relationship { password customerid } } }",
          "variables": {}
        }
      """
      payload_variable = 'where: {email: {_ilike: \\"$email$\\"}}'.replace('$email$', email_new)
      payload_password_email_query = payload_password_email_query.replace('$variable$', payload_variable)
      app.logger.info(payload_password_email_query)
      email_customerid_response = requests.request("POST", url, headers=headers, data=payload_password_email_query).json()
      app.logger.info(email_customerid_response)
      if email_customerid_response["data"]["customer_data"] == []:
        flask_response = update_headers(make_response(jsonify({
          "message": "No data found for given email"
        }), 404))
        return flask_response
      customerid = email_customerid_response["data"]["customer_data"][0]["customer_password_relationship"]["customerid"]
      customer_hashed_password = email_customerid_response["data"]["customer_data"][0]["customer_password_relationship"]["password"]
      is_password_correct = verify_password(password, customer_hashed_password)
      if is_password_correct:
        flask_response = update_headers(make_response(jsonify({
          "message": "password is correct"
        }), 200))
        expiration_time = datetime.datetime.now() + datetime.timedelta(days=1)
        flask_response.set_cookie('customer_product_cookie', generateJWTToken(customerid), expires=expiration_time)
      else:
        flask_response = update_headers(make_response(jsonify({
          "message": "password is incorrect"
        }), 400))
      return flask_response
    
    elif login_data.get("mobile") not in ["", None]:
      mobile = login_data.get("mobile")
      mobile_new  = mobile[-10:]
      payload_password_mobile_query = """
        {
          "query": "query MyQuery { customer_data($variable$) { customer_password_relationship { password customerid } } }",
          "variables": {}
        }
      """
      payload_variable = 'where: {_or: [{mobile: {_eq: \\"$mobile$\\"}}, {phone: {_eq: \\"$mobile$\\"}}]}'.replace('$mobile$', mobile_new)
      payload_password_mobile_query = payload_password_mobile_query.replace('$variable$', payload_variable)
      app.logger.info(payload_password_mobile_query)
      mobile_customerid_response = requests.request("POST", url, headers=headers, data=payload_password_mobile_query).json()
      app.logger.info(mobile_customerid_response)
      if mobile_customerid_response["data"]["customer_data"] == []:
        flask_response = update_headers(make_response(jsonify({
          "message": "No data found for given mobile"
        }), 404))
        return flask_response
      customerid = mobile_customerid_response["data"]["customer_data"][0]["customer_password_relationship"]["customerid"]
      customer_hashed_password = mobile_customerid_response["data"]["customer_data"][0]["customer_password_relationship"]["password"]
      is_password_correct = verify_password(password, customer_hashed_password)
      if is_password_correct:
        flask_response = update_headers(make_response(jsonify({
          "message": "password is correct"
        }), 200))
        expiration_time = datetime.datetime.now() + datetime.timedelta(days=1)
        flask_response.set_cookie('customer_product_cookie', generateJWTToken(customerid), expires=expiration_time)
      else:
        flask_response = update_headers(make_response(jsonify({
          "message": "password is incorrect"
        }), 400))
      return flask_response
    
    else:
      flask_response = update_headers(make_response(jsonify({
          "message": "Atleast one email, mobile or customerid should be provided"
        }), 400))
      return flask_response

@app.route('/add-new-product', methods=['POST'])
def add_new_product():
  cookies = request.cookies
  response_verification_or_customerid, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification_or_customerid), resposne_code))
  customerid = response_verification_or_customerid
  product_attributes = request.json
  product_mandatory_attributes = {
    "payment_frequency": r"^(Monthly|Annually|Semi-Annually|Quarterly)$",
    "product_pricing": r"^\d+$",
    "productid": r"^[a-zA-Z0-9]+$",
    "productname": r"^[a-zA-Z0-9\s]+$"
  }
  for item in product_mandatory_attributes.keys():
    if product_attributes.get(item) in ["", None]:
      flask_response = update_headers(make_response(jsonify({
          "message": f"{item} is mandatory attributes"
        }), 400))
      return flask_response
  for name, rege in product_mandatory_attributes.items():
    pattern = re.compile(rege)
    tp_match = product_attributes.get(name)
    if not bool(re.fullmatch(pattern, tp_match)):
      flask_response = update_headers(make_response(jsonify({
          "message": f"{name}.{tp_match} is not in correct format"
        }), 400))
      return flask_response
  admin_checking_auery = """
      {
        "query": "query MyQuery { customer_data($variable$) { customerid isadmin } } "
      }
  """
  payload_admin_variable = 'where: {customerid: {_eq: \\"$customerid$\\"}}'.replace('$customerid$', customerid)
  admin_checking_query = admin_checking_auery.replace('$variable$', payload_admin_variable)
  app.logger.info(admin_checking_query)
  admin_verify_response = requests.request("POST", url, headers=headers, data=admin_checking_query).json()
  app.logger.info(admin_verify_response)
  if admin_verify_response["data"]["customer_data"] == []:
    flask_response = update_headers(make_response(jsonify({
      "message": "No data found for mentioned customerid"
    }), 404))
    return flask_response
  admin_flag = admin_verify_response["data"]["customer_data"][0]["isadmin"]
  if admin_flag != 'Y':
    flask_response = update_headers(make_response(jsonify({
      "message": "You have insufficient permission"
    }), 401))
    return flask_response
  product_attribute_update_payload = f'payment_frequency: \\"{product_attributes.get("payment_frequency")}\\", product_pricing: \\"{'₹' + product_attributes.get("product_pricing")}\\", productid: \\"{product_attributes.get("productid")}\\", productname: \\"{product_attributes.get("productname")}\\", unique_identifier: \\"{str(uuid.uuid4())}\\", updated_timestamp: \\"{str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))}\\"'
  product_attribute_update_query = """
    {
      "query":"mutation MyMutation {  insert_product_attributes(objects: {$variable$}) {    returning {      payment_frequency      product_pricing      productid      productname   unique_identifier  updated_timestamp  }    affected_rows  }}",
      "variables":{}
    }
  """
  product_attribute_update_query = product_attribute_update_query.replace('$variable$', product_attribute_update_payload)
  app.logger.info(product_attribute_update_query)
  product_attribute_update_response = requests.request("POST", url, headers=headers, data=product_attribute_update_query).json()
  app.logger.info(product_attribute_update_response)
  if product_attribute_update_response["data"]["insert_product_attributes"]["returning"] == []:
    flask_response = update_headers(make_response(jsonify({
      "message": "Something Went Wrong"
    }), 500))
  else:
    flask_response = update_headers(make_response(jsonify({
        "message": "Product Added Successfully"
      }), 200))
  return flask_response 

@app.route('/update-product', methods=['POST'])
def update_product():
  cookies = request.cookies
  response_verification_or_customerid, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification_or_customerid), resposne_code))
  customerid = response_verification_or_customerid
  product_attributes = request.json
  product_mandatory_attributes = {
    "payment_frequency": r"^(Monthly|Annually|Semi-Annually|Quarterly|None|)$",
    "product_pricing": r"^(\d+|None|)$",
    "productid": r"^[a-zA-Z0-9]+$",
    "productname": r"^([a-zA-Z0-9\s]+|None|)$"
  }
  product_mandatory_list = ["productid"]
  for item in product_mandatory_list:
    if product_attributes.get(item) in ["", None]:
      flask_response = update_headers(make_response(jsonify({
          "message": f"{item} is mandatory attributes"
        }), 400))
      return flask_response
  for name, rege in product_mandatory_attributes.items():
    pattern = re.compile(rege)
    tp_match = str(product_attributes.get(name))
    if not bool(re.fullmatch(pattern, tp_match)):
      flask_response = update_headers(make_response(jsonify({
          "message": f"{name}.{tp_match} is not in correct format"
        }), 400))
      return flask_response
  admin_checking_auery = """
      {
        "query": "query MyQuery { customer_data($variable$) { customerid isadmin } } "
      }
  """
  payload_admin_variable = 'where: {customerid: {_eq: \\"$customerid$\\"}}'.replace('$customerid$', customerid)
  admin_checking_query = admin_checking_auery.replace('$variable$', payload_admin_variable)
  app.logger.info(admin_checking_query)
  admin_verify_response = requests.request("POST", url, headers=headers, data=admin_checking_query).json()
  app.logger.info(admin_verify_response)
  if admin_verify_response["data"]["customer_data"] == []:
    flask_response = update_headers(make_response(jsonify({
      "message": "No data found for mentioned customerid"
    }), 404))
    return flask_response
  admin_flag = admin_verify_response["data"]["customer_data"][0]["isadmin"]
  if admin_flag != 'Y':
    flask_response = update_headers(make_response(jsonify({
      "message": "You have insufficient permission"
    }), 401))
    return flask_response
  keys, values = list(product_attributes.keys()).copy(), list(product_attributes.values()).copy()
  for key, value in zip(keys, values):
    if value in ["", 'None']:
      product_attributes.pop(key)
  product_attributes["unique_identifier"] = str(uuid.uuid4())
  product_attributes["updated_timestamp"] = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
  if product_attributes.get("product_pricing") != None:
    product_attributes["product_pricing"] = '₹' + product_attributes["product_pricing"]

  product_attribute_update_query = """
    {
      "query":"mutation MyMutation { update_product_attributes(where: {productid: {_eq: \\"$productid$\\"}}, _set: $variable$) { returning { productid } affected_rows } }",
      "variables":{}
    }
  """
  product_attribute_update_query = product_attribute_update_query.replace('$variable$', json.dumps(product_attributes).replace('"', '\\"')).replace('$productid$', product_attributes["productid"])
  for key in product_attributes.keys():
    app.logger.info(f'\\"{key}\\"')
    product_attribute_update_query = product_attribute_update_query.replace(f'\\"{key}\\"', key)
  app.logger.info(product_attribute_update_query)
  product_attribute_update_response = requests.request("POST", url, headers=headers, data=product_attribute_update_query).json()
  app.logger.info(product_attribute_update_response)
  if product_attribute_update_response["data"]["update_product_attributes"]["returning"] == []:
    flask_response = update_headers(make_response(jsonify({
      "message": "Something Went Wrong or product code does not exist"
    }), 500))
  else:
    flask_response = update_headers(make_response(jsonify({
        "message": "Product Updated Successfully"
      }), 200))
  return flask_response 

@app.route('/pay-payment', methods=['POST'])
def pay_payment():
  cookies = request.cookies
  response_verification_or_customerid, resposne_code = verify_cookie_token(cookies)
  if resposne_code != None:
    return update_headers(make_response(jsonify(response_verification_or_customerid), resposne_code))
  payment_attributes = request.json
  payment_mandatory_attributes = {
    "customerid": r"^[a-zA-Z0-9]+$",
    "payment_amount": r"^(\d+)$",
    "payment_mode": r"^(Online|UPI|Card|Net-Banking)$",
    "payment_timestamp": r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{4}|None|",
    "productid": r"^[a-zA-Z0-9]+$",
    "productstatus": r"^(Active|InActive|None|)$"
  }
  payment_mandatory_list = ["customerid", "payment_amount", "payment_mode", "productid"]
  for item in payment_mandatory_list:
    if payment_attributes.get(item) in ["", None]:
      flask_response = update_headers(make_response(jsonify({
          "message": f"{item} is mandatory attributes"
        }), 400))
      return flask_response
  for name, rege in payment_mandatory_attributes.items():
    pattern = re.compile(rege)
    tp_match = str(payment_attributes.get(name))
    if not bool(re.fullmatch(pattern, tp_match)):
      flask_response = update_headers(make_response(jsonify({
          "message": f"{name}.{tp_match} is not in correct format"
        }), 400))
      return flask_response
    
  if response_verification_or_customerid != payment_attributes["customerid"]:
    flask_response = update_headers(make_response(jsonify({
          "message": "Please log in with correct customer id"
        }), 400))
    return flask_response
  
  query_checking_customerid = """
    {
      "query":"query MyQuery { customer_data($variable$) { customerid } } ",
      "variables":{}
    }
  """
  payload_customerid = 'where: {customerid: {_eq: \\"$customerid$\\"}}'
  query_checking_customerid = query_checking_customerid.replace('$variable$', payload_customerid).replace('$customerid$', response_verification_or_customerid)
  app.logger.info(query_checking_customerid)
  customerid_existing_response = requests.request("POST", url, headers=headers, data=query_checking_customerid).json()
  if customerid_existing_response["data"]["customer_data"] == []:
    flask_response = update_headers(make_response(jsonify({
          "message": "No data found for mentioned customer id"
        }), 404))
    return flask_response
  
  query_checking_productid = """
    {
      "query":"query MyQuery { product_attributes($variable$) { productid } } ",
      "variables":{}
    }
  """
  payload_checking_productid = 'where: {productid: {_eq: \\"$productid$\\"}}'.replace('$productid$', payment_attributes["productid"])
  query_checking_productid = query_checking_productid.replace('$variable$', payload_checking_productid)
  app.logger.info(query_checking_productid)
  productid_existing_response = requests.request("POST", url, headers=headers, data=query_checking_productid).json()
  app.logger.info(productid_existing_response)
  if productid_existing_response["data"]["product_attributes"] == []:
    flask_response = update_headers(make_response(jsonify({
          "message": "No data found for mentioned product id"
        }), 404))
    return flask_response
  
  payment_attributes["unique_identifier"] = str(uuid.uuid4())
  payment_attributes["updated_timestamp"] = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
  payment_attributes["payment_amount"] = '₹' + payment_attributes["payment_amount"]
  if payment_attributes.get("payment_timestamp") in [None, ""]:
    payment_attributes["payment_timestamp"] = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
  query_pay_payment = """
    {
      "query":"mutation MyMutation { insert_product_customer_relation(objects: $variable$) { affected_rows returning { customerid productid } } }",
      "variables":{}
    }
  """
  query_pay_payment = query_pay_payment.replace('$variable$', json.dumps(payment_attributes).replace('"', '\\"'))
  for key in payment_attributes.keys():
    app.logger.info(f'\\"{key}\\"')
    query_pay_payment = query_pay_payment.replace(f'\\"{key}\\"', key)
  app.logger.info(query_pay_payment)

  payment_response = requests.request("POST", url, headers=headers, data=query_pay_payment).json()
  app.logger.info(payment_response)
  if payment_response["data"]["insert_product_customer_relation"]["returning"] != []:
    flask_response = update_headers(make_response(jsonify({
          "message": "Payment Recorded successfully"
        }), 200))
  else:
    flask_response = update_headers(make_response(jsonify({
            "message": "Something Went Wrong"
          }), 500))
  return flask_response

@app.route('/signup', methods=['POST'])
def signup():
  signup_attributes = request.json
  signup_mandatory_attributes = {
  "customer_data": {
      "address1": r"^[a-zA-Z0-9\s]+|None|$",
      "address2": r"^[a-zA-Z0-9\s]+|None|$",
      "address3": r"^[a-zA-Z0-9\s]+|None|$",
      "adhar": r"^\d{4}\d{4}\d{4}$",
      "city": r"^[a-zA-Z0-9\s]+|None|$",
      "country": r"^[a-zA-Z0-9\s]+|None|$",
      "customerid": r"^[a-zA-Z0-9]+|None|$",
      "dob": r"^\d{4}-\d{2}-\d{2}$",
      "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
      "gender": r"^M|F$",
      "isadmin": r"^N|None|$",
      "mobile": r"^(?:\+91)?\d{1,11}$",
      "name": r"^[a-zA-Z0-9\s]+|None|$",
      "pan": r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$",
      "pincode": r"^[1-9][0-9]{5}$|None|$",
      "phone": r"^(?:\+91)?\d{1,11}$",
      "state": r"^[a-zA-Z0-9\s]+|None|$"
    },
    "customer_password_array_relation": {
      "password": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])[a-zA-Z\d\W_]{8,}$"
    },
    "customer_product_details": {
      "payment_amount": r"^(\d+)$",
      "payment_mode": r"^(Online|UPI|Card|Net-Banking)$",
      "payment_timestamp": r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{4}|None|",
      "productid": r"^[a-zA-Z0-9]+$",
      "productstatus": r"^(Active|InActive|None|)$"
    }
  }
  productid = signup_attributes["customer_product_details"]["productid"]
  payload_productid = '{"query":"query MyQuery { product_attributes(where: {productid: {_eq: \\"$productid$\\"}}) { payment_frequency product_pricing productid productname unique_identifier updated_timestamp } }","variables":{}}'.replace('$productid$', productid)
  response_productid = requests.request("POST", url, headers=headers, data=payload_productid).json()
  if response_productid["data"]["product_attributes"] == []:
    flask_response = update_headers(make_response(jsonify({
       "message": f"{productid} is not present in database"
    }), 404))
    return flask_response

  for item in signup_mandatory_attributes.keys():
    if signup_attributes.get(item) == None and type(signup_attributes.get(item)).__name__ != type(signup_mandatory_attributes[item]).__name__:
      flask_response = update_headers(make_response(jsonify({
            "message": f"{item} is mandatory attribute"
          }), 400))
      return flask_response
  
  for item in signup_mandatory_attributes.keys():
    need_to_be_checked_json = signup_attributes[item]
    rege_json = signup_mandatory_attributes[item]
    for name, rege in rege_json.items():
      pattern = re.compile(rege)
      tp_match = str(need_to_be_checked_json.get(name))
      if 'None' not in rege and tp_match == 'None':
        flask_response = update_headers(make_response(jsonify({
            "message": f"{item}.{name}.{tp_match} is mandatory attribute"
          }), 400))
        return flask_response
      if not bool(re.fullmatch(pattern, tp_match)):
        message = f"{item}.{name}.{tp_match} is not in correct format"
        if tp_match == 'password':
          message = message + ', Minimum eight characters, at least one uppercase letter, one lowercase letter and one number and a special character'
        flask_response = update_headers(make_response(jsonify({
            "message": message
          }), 400))
        return flask_response

  signup_attributes["customer_data"]["customerid"] = str(uuid.uuid4()).replace('-', '') if signup_attributes["customer_data"].get("customerid") in [None, '', ] else signup_attributes["customer_data"].get("customerid")
  signup_attributes["customer_data"]["isadmin"] = 'N' if signup_attributes["customer_data"].get("isadmin") in [None, '', ] else signup_attributes["customer_data"].get("isadmin")
  signup_attributes["customer_product_details"]["payment_amount"] = '₹' + signup_attributes["customer_product_details"]["payment_amount"]

  multpl_eml_phn_mbl_pan_adhr_cstmrd_vrbl = 'where: {_or: [{mobile: {_eq: \\"$mobile$\\"}}, {phone: {_eq: \\"$phone$\\"}}, {email: {_ilike: \\"$email$\\"}}, {pan: {_eq: \\"$pan$\\"}}, {adhar: {_eq: \\"$adhar$\\"}}, {customerid: {_eq: \\"customerid\\"}} ]}'.replace(
    '$mobile$', signup_attributes["customer_data"].get("mobile")
  ).replace(
    '$phone$', signup_attributes["customer_data"].get("phone")
  ).replace(
    '$pan$', signup_attributes["customer_data"].get("pan")
  ).replace(
    '$adhar$', signup_attributes["customer_data"].get("adhar")
  ).replace(
    '$email$', signup_attributes["customer_data"].get("email")
  ).replace(
    '$customerid$', signup_attributes["customer_data"].get("customerid")
  )
  
  multpl_eml_phn_mbl_pan_adhr_cstmrd_qry = """
  {
    "query": "query MyQuery { customer_data($variable$) { mobile phone email pan adhar customerid } }",
    "variables": {}
  }
  """.replace('$variable$', multpl_eml_phn_mbl_pan_adhr_cstmrd_vrbl)

  app.logger.info(multpl_eml_phn_mbl_pan_adhr_cstmrd_qry)
  eml_phn_mbl_pan_adhr_cstmrd_rsp = requests.request("POST", url, headers=headers, data=multpl_eml_phn_mbl_pan_adhr_cstmrd_qry).json()
  app.logger.info(eml_phn_mbl_pan_adhr_cstmrd_rsp)
  if eml_phn_mbl_pan_adhr_cstmrd_rsp["data"]["customer_data"] != []:
    flask_response = update_headers(make_response(jsonify({
            "message": f"failure keys  {', '.join(list(eml_phn_mbl_pan_adhr_cstmrd_rsp["data"]["customer_data"][0].keys()))} already exist in database"
          }), 500))
    return flask_response
  
  signup_attributes["customer_password_array_relation"]["password"] = hash_password_func(signup_attributes["customer_password_array_relation"]["password"])
  signup_attributes["customer_password_array_relation"]["unique_identifier"] = str(uuid.uuid4())
  signup_attributes["customer_password_array_relation"]["updated_timestamp"] = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
  signup_attributes["customer_data"]["unique_identifier"] = str(uuid.uuid4())
  signup_attributes["customer_data"]["updated_timestamp"] = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
  signup_attributes["customer_product_details"]["unique_identifier"] = str(uuid.uuid4())
  signup_attributes["customer_product_details"]["updated_timestamp"] = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))

  signup_attributes["customer_product_details"]["productstatus"] = 'Active' if signup_attributes["customer_product_details"].get("productstatus") in [ None, '' ] else signup_attributes["customer_product_details"]["productstatus"]
  signup_attributes["customer_product_details"]["payment_timestamp"] = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')) if signup_attributes["customer_product_details"].get("payment_timestamp") in [ None, '' ] else signup_attributes["customer_product_details"]["payment_timestamp"]

  customer_data_json_dumps = ''
  customer_product_details_json_dumps = ''
  customer_password_array_relation_json_dumps = ''

  for key in signup_attributes.keys():
    if key == 'customer_data':
      customer_data_json_dumps = json.dumps(signup_attributes["customer_data"])
      for key_in in signup_attributes["customer_data"].keys():
        customer_data_json_dumps = customer_data_json_dumps.replace('"' + key_in + '"', key_in)

    elif key == 'customer_product_details':
      customer_product_details_json_dumps = json.dumps(signup_attributes["customer_product_details"])
      for key_in in signup_attributes["customer_product_details"].keys():
        customer_product_details_json_dumps = customer_product_details_json_dumps.replace('"' + key_in + '"', key_in)

    elif key == 'customer_password_array_relation':
      customer_password_array_relation_json_dumps = json.dumps(signup_attributes["customer_password_array_relation"])
      for key_in in signup_attributes["customer_password_array_relation"].keys():
        customer_password_array_relation_json_dumps = customer_password_array_relation_json_dumps.replace('"' + key_in + '"', key_in)
        
  query_signup_payload = """mutation MyMutation { insert_customer_data ( objects: { $customer_data$, customer_product_details: { data: [ $customer_product_details$ ] }, customer_password_array_relation: { data: [ $customer_password_array_relation$ ] }, } ) { affected_rows returning { customerid } } }""".replace('$customer_data$', customer_data_json_dumps.replace('{', '').replace('}', ''))\
  .replace('$customer_product_details$', customer_product_details_json_dumps)\
  .replace('$customer_password_array_relation$', customer_password_array_relation_json_dumps)\
  .replace('"', '\\"')

  query_signup = """
    {
      "query": "$query_signup_payload$",
      "variables":{}
    }
  """.replace('$query_signup_payload$', query_signup_payload)
  
  app.logger.info(query_signup)
  signup_response = requests.request("POST", url, headers=headers, data=query_signup).json()
  if signup_response.get("data").get("insert_customer_data").get("returning") in [[], None]:
    flask_response = update_headers(make_response(jsonify({
            "message": "Something went wrong"
          }), 500))
  customerid_resp = signup_response.get("data").get("insert_customer_data").get("returning")[0]["customerid"]
  expiration_time = datetime.datetime.now() + datetime.timedelta(days=1)
  flask_response = update_headers(make_response(jsonify({
            "message": f"Signed in successfully, your id is {customerid_resp}"
          }), 200))
  flask_response.set_cookie('customer_product_cookie', generateJWTToken(customerid_resp), expires=expiration_time)
  return flask_response

    
# if __name__ == '__main__':
#    app.run(host='0.0.0.0', port=23002)