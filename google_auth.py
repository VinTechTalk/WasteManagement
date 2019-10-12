#!/usr/bin/env python3
"""Minimal Google login using OAuth 2.0 and the library oauth2client.

oauth2client has been deprecated in favor for google-auth. This
code, however, still works fine as of 12-03-2019."""

import os
import string
import random
import httplib2
import requests
import pickle 

import stripe

import sys
import glob
import re

from tensorflow import keras
from keras.models import load_model



from PIL import Image
import pickle

from flask import request
from flask import Flask, jsonify, request, render_template, url_for, redirect, make_response
from keras.applications.imagenet_utils import preprocess_input, decode_predictions
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
#import gspread
from oauth2client.service_account import ServiceAccountCredentials
from sklearn.externals import joblib
from werkzeug.utils import secure_filename
from keras.preprocessing import image
import numpy as np

from google.oauth2 import credentials
from OpenSSL import SSL
import json
import sqlite3
import click
from flask import current_app, g
from flask.cli import with_appcontext


#client_secrets_file = open('instance/client_secrets').read()
#client_secrets = json.loads(client_secrets_file).get('web')

#client_secrets = {"web":{"client_id":"2624369029-jp4kvug4imk1nfqt2n9eq6197nic5ol5.apps.googleusercontent.com","project_id":"item-catalog-185316","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://accounts.google.com/o/oauth2/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"cd_HD5wmijZJre3SX2rykj6-","redirect_uris":["http://localhost:5000/gconnect","http://localhost:5000/login","http://localhost:5000/gdisconnect","http://ec2-54-164-37-123.compute-1.amazonaws.com"],"javascript_origins":["http://localhost:5000","http://ec2-52-11-206-40.us-west-2.compute.amazonaws.com"]}}
client_secrets =  json.loads(open('google_oauth2_client.json', 'r').read())['web']['client_id']

MODEL_PATH = 'best.hdf5' 
#MODEL_PATH = 'sep_recyclable_v2.h5'

# Load your trained model
#model = joblib.load(MODEL_PATH)

model = load_model(MODEL_PATH)
#model = pickle.load(open(MODEL_PATH, 'rb'))
#model._make_predict_function()          # Necessary

app = Flask(__name__)

app.secret_key = '#if~you^can_read*this=it`s-too+late'



SECRET_STRIPE_KEY = 'sk_test_2CJHIv4WfHYYWkOpGsyHGI1F'
PUBLISHABLE_KEY = 'pk_test_8zlZgHy67wX0VfHzCbwDXf9Q'

stripe_keys = {
    'secret_key': SECRET_STRIPE_KEY,
    'publishable_key': PUBLISHABLE_KEY
    }

stripe.api_key = stripe_keys['secret_key']



@app.route('/index/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', key=stripe_keys['publishable_key'])

@app.route('/pay')
def pay():
    """
    """
    amount = 0 # cents
    customer = stripe.Customer.create(
        email='shwetabh.sharan@forgeahead.io',
        source=request.form['stripeToken'])

    charge = stripe.Charge.create(customer=customer.id,
                                  amount=amount, currency='usd',
                                  description='subscription payment')

    return render_template('pay.html', amount=amount)


def select_task_by_priority(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM Users")
    rows = cur.fetchall()
    return rows

def GetUserApiUseCount():
    conn = sqlite3.connect(get_db())
    cur = conn.cursor()
    test = cur.execute("SELECT ApiUseCount FROM Users where UserName = ?", [login_session['username']])
    count = cur.fetchall()
    return count


@app.route('/predict', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # Get the file from post request
        f = request.files['image']
        # Save the file to ./uploads
        basepath = os.path.dirname(__file__)
        file_path = os.path.join(
            basepath, 'uploads', secure_filename(f.filename))
        f.save(file_path)

        userApiUseCount = GetUserApiUseCount()[0]
        
        if(userApiUseCount[0] != None ):
            # Make prediction
            model = keras.models.load_model('sep_recyclable_v2_1.h5')
            with open('labels.p', 'rb') as fp:
                labels = pickle.load(fp)
            img  = Image.open("cardboard399.jpg")
            img = img.resize((224,224))
            im2arr = np.array(img)
            im2arr = im2arr.reshape(1,224,224,3)
            y_pred = model.predict_classes(im2arr)
            prediction = labels[y_pred[0]]
            result = prediction
        else:
            result = "Please subscribe to use the service"
        return result
    return None

def model_predict(img_path, model):
    img = image.load_img(img_path, target_size=(224, 224))

    # Preprocessing the image
    x = image.img_to_array(img)
    # x = np.true_divide(x, 255)
    x = np.expand_dims(x, axis=0)

    # Be careful how your trained model deals with the input
    # otherwise, it won't make correct prediction!
    #x = preprocess_input(x, mode='caffe')

    preds = model.predict(x)
    return preds

def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by the db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = sqlite3.connect(db_file)
    return conn

def get_db():
    database = r"G:\Projects\Google signin template_Flask\WasteManagement.db"
    conn = create_connection(database)
    test = select_task_by_priority(conn)
    return database
    #return g.db

def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()   

@app.route('/')
@app.route('/login/')
def login():
    #get_db()
    template_args = {}
    passthrough_value = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = passthrough_value
    template_args['state'] = login_session['state']
    return render_template('login.html', args=template_args)

# @app.route('/Home/')
# def Home():
#     template_args = {}
#     template_args['state'] = login_session['state']

#     userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
#     #params = {'access_token': credentials.Credentials.id_token, 'alt': 'json'}
#     #test1 = credentials._GOOGLE_OAUTH2_TOKEN_ENDPOINT
#     #test1 = credentials.Credentials
#     #test3 = credentials.json
#     #answer = requests.get(userinfo_url, params=params)
#     #data = answer.json()

#     return render_template('Home.html', args = template_args)



@app.route('/register', methods=['POST'])
def register():
    #fullname = request.args.get('fullName') 
    content = request.data
    data = json.loads(content.decode("utf-8").replace("'", '"'))

    fullname = data['fullName']
    email = data['email']
    password = data['password']
    conn = sqlite3.connect(get_db())

    cursor = conn.cursor()

    sqlite_insert_with_param = """INSERT INTO 'Users'
                          ('UserName', 'Password', 'EmailAddress', 'IsGoogleSignin', 'FullName') 
                          VALUES (?, ?, ?, ?, ?);"""

    data_tuple = (email, password, email, False,fullname)
    cursor.execute(sqlite_insert_with_param, data_tuple)
    conn.commit()
    cursor.close()
    
    # conn.execute("INSERT INTO Users (UserName,Password,EmailAddress,IsGoogleSignin) \
    #      VALUES (1, 'Paul', 32, 'California', 20000.00 )")
    #return render_template('login2.html')

    
@app.route('/login/gconnect', methods=['GET', 'POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        return 'Fail'
    #flow = flow_from_clientsecrets('instance/client_secrets',
     #                           scope='https://www.googleapis.com/auth/userinfo.email',
     #                           redirect_uri=client_secrets.get('redirect_uris')[0])
    flow = flow_from_clientsecrets(
            'google_oauth2_client.json', scope='')
    flow.redirect_uri = 'http://localhost:5000/Home'
    flow.scope = 'https://www.googleapis.com/auth/userinfo.email'
    # Redirect the user to auth_uri on your platform.
    auth_uri = flow.step1_get_authorize_url()
    #test = login_session['state']
    
    #login_session['flow'] = flow
    return redirect(auth_uri)


#@app.route('/login/authorized')
@app.route('/Home/')
def callback():
    code = request.args.get('code')
    # Pass code provided by authorization server redirection to this function
    #flow = flow_from_clientsecrets('google_oauth2_client',
    #                            scope='https://www.googleapis.com/auth/userinfo.email',
    #                            redirect_uri= 'http://localhost:5000/Home') 
    flow = flow_from_clientsecrets(
            'google_oauth2_client.json', scope='', redirect_uri= 'http://localhost:5000/Home')
    credentials = flow.step2_exchange(code)
    # Supply access token to information request using httplib2
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.\
        format(access_token))
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # Check user is not already logged in using gconnect
    gplus_id = credentials.id_token['sub']
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    # if stored_credentials != None and gplus_id == stored_gplus_id:
    #     response = make_response(
    #         json.dumps("Current user is already connected."), 200
    #     )
    #     response.headers['Content-Type'] = 'application/json'
    #     return response
    # Store the access token in session for later use
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['email']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    return render_template('Home.html')
    #return 'Code: {}, credentials: {}, result: {}, email: {}'.format(code, credentials, result, login_session['username'])
    

#def main():
    #app.secret_key = 'a_very_secret_key'
    if __name__ == '__main__':
	    app.debug = True
	    app.secret_key = '#if~you^can_read*this=it`s-too+late'
	    #app.run(host='localhost', port=8080, debug=True)



