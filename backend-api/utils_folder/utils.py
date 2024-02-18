import os
import bcrypt
import datetime
import jwt

hasura_api_key = os.getenv("HASURA_API_KEY")
hasura_api_value = os.getenv("HASURA_API_VALUE")
secret_value_jwt = os.getenv("SECRET_KEY")

url = "http://graphql-engine:8080/v1/graphql"

headers = {
  'Content-Type': 'application/json',
  hasura_api_key: hasura_api_value
}

def verify_cookie_token(cookies):
  cookies_dict = dict(cookies)
  jwt_token = cookies_dict.get("customer_product_cookie")
  if jwt_token is None:
    return {
      "message": "Cookie is not Present or Please login Again"
    }, 401
  customerid_jwt_token = verifyJWTToken(jwt_token)
  if customerid_jwt_token in [ None ]:
    return {
      "message": "Cookie is not Valid"
    }, 401
  else:
    return customerid_jwt_token, None
  
def hash_password_func(password):
  salt = bcrypt.gensalt()
  hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
  return hashed_password.decode('utf-8')

def verify_password(password, hashed_password):
  provided_hash = bcrypt.hashpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
  if provided_hash.decode("utf-8") == hashed_password:
    return True
  else:
    return False

def generateJWTToken(payload_customerid):
  expiry_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
  payload = {
            "sub": "account_aggregator",
            "iss": "account_aggregator token generation",
            "customerid": payload_customerid,
            "exp": expiry_time
        }
  jwt_token = jwt.encode(payload, secret_value_jwt, algorithm="HS256")
  return jwt_token

def verifyJWTToken(jwt_token):
    try:
        payload = jwt.decode(jwt_token, secret_value_jwt, algorithms=["HS256"])
        customerid = payload.get('customerid')
        return customerid
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None

def update_headers(resp):
  resp.headers['Access-Control-Allow-Origin'] = "*"
  resp.headers['Strict-Transport-Security'] = "max-age=31536000"
  resp.headers['X-Frame-Options'] = "DENY"
  resp.headers['Content-Security-Policy'] = "default-src 'none'"
  resp.headers['X-Content-Type-Options'] = "nosniff"
  resp.headers['Content-Type'] = "application/json"
  return resp

