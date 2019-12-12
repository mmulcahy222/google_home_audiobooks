from flask import Flask, request
import os,sys,json,time
from google.cloud import storage
from google.oauth2 import service_account

def lambda_handler(request):
    try:
        #This happens INSIDE of Google Functions with no interaction with Amazon AWS Lambda
        #NOTE: You will have to make a Service Account for this
        #https://cloud.google.com/docs/authentication/production
        #https://console.cloud.google.com/apis/credentials/serviceaccountkey
        request_json = get_request(request)
        choice = get_parameter(request_json,'any')
        blobs_in_storage = get_blobs_in_bucket('mystoragebucket')
        blob_file_object = get_blob_by_part(blobs_in_storage,choice)
        #get url right in here
        audio_url = blob_file_object.generate_signed_url(int(time.time() + 3600))
        return google_return(build_response(audio_url))
    except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        exception_text = str(exc_type) + ' ' + str(exc_obj) + ' ' + str(exc_tb.tb_lineno)
        return google_return(exception_text)

def get_request(request):
    #only purpose is for portability between windows system & google functions
    if os.name == 'nt':
        return request
    else:
        return request.get_json()

def handle_exception(func):
    def wrapper(*args,**kwargs):
        try:
            return func(*args,**kwargs)
        except:
            return False
    return wrapper

#get request value
@handle_exception    
def get_parameter(response_json,key,value=False):
    return response_json.get('queryResult').get('parameters').get(key)

@handle_exception
def get_blob_by_part(list, part):
    return [value for value in list if part in value.name][0]

def get_blobs_in_bucket(bucket_name):
    """Lists all the blobs in the bucket."""
    storage_client = get_client()
    bucket = storage_client.get_bucket(bucket_name)
    blobs = bucket.list_blobs()
    return list(blobs)

def build_response(audio_url):
    response_json = {
        #"fulfillmentText": str(speech_output),
        "payload": {
            "google": {
                "richResponse": {
                    "items": [
                        {
                            "simpleResponse": {
                                "textToSpeech": "Reading Audiobook"
                            }
                        }
                        ,
                        {
                            "mediaResponse": {
                                "mediaType": "AUDIO",
                                "mediaObjects": [
                                    {
                                        "contentUrl": str(audio_url),
                                        "description": "Audio Book",
                                        "name": "Audio Book"
                                    }
                                ]
                            }
                        }
                    ]
                    ,
                    "suggestions": [
                        {
                            "title": "Suggestion"
                        }
                    ]
                }
            }
        }
    }
    return json.dumps(response_json)

def google_return(text):
    return (text, 200, {"Content-Type":"application/json"})

def get_client():
    #The purpose is to do temporary signed URLS with a special client
    #
    #if windows
    if os.name == 'nt':
        return storage.Client.from_service_account_json(
        'xxx')
    #if in google cloud
    else:
        #https://googleapis.github.io/google-cloud-python/latest/core/auth.html
        #https://google-auth.readthedocs.io/en/latest/user-guide.html#service-account-private-key-files
        #https://google-auth.readthedocs.io/en/latest/user-guide.html#application-default
        auth_json = {
          "type": "service_account",
          "project_id": "read-agent",
          "private_key_id": "NUNYA BUSINESS",
          "private_key": "Nobody's business",
          "client_email": "opaline-goonery-service@read-agent.iam.gserviceaccount.com",
          "client_id": "NUNYA BUSINESS",
          "auth_uri": "https://accounts.google.com/o/oauth2/auth",
          "token_uri": "https://oauth2.googleapis.com/token",
          "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
          "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/NUNYA BUSINESS"
        }
        credentials = service_account.Credentials.from_service_account_info(auth_json)
        scoped_credentials = credentials.with_scopes(['https://www.googleapis.com/auth/cloud-platform'])
        return storage.Client(credentials=credentials)
 

