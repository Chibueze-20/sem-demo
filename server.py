from __future__ import division, print_function
# coding=utf-8
import sys
import os
import glob
import re
import shutil
import numpy as np
import pandas as pd
from zipfile import ZipFile
import dtype as dt
# import tracemalloc
# Flask utils
from flask import Flask, redirect, url_for, request,make_response, render_template, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from gevent.pywsgi import WSGIServer
from flask.helpers import flash, send_file, send_from_directory

# Define a flask app
app = Flask(__name__,)

CORS(app)

app.config['DATASET'] = 'Dataset'
app.config['REPORT'] = 'Dataset\\temp'
app.config['DAY']=None
dataframeAll = None
name = ''
def makecsv(path,filename):
    allfiles = [f.path for f in os.scandir(path)]
    ddf = pd.read_csv(allfiles[0],header=None,names=dt.columns(),dtype=dt.Dtype())
    for i in range(1,len(allfiles)):
        ddf.append(pd.read_csv(allfiles[i],header=None,names=dt.columns(),dtype=dt.Dtype()))
    return ddf

def unzip(file,filename):
    with ZipFile(file,'r') as zipObj:
        zipObj.extractall('Dataset\\'+filename)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['zip']

@app.route('/', methods=['GET'])
def index():
    if name=='':
        allfiles=[]
    else:
        allfiles=[name]
    # Main page
    return render_template('index.html',files=allfiles)

@app.route('/data/<name>',methods=['GET'])
def load_day(name=None):
    try:
        if name =='' or dataframeAll == None:
            return redirect(url_for('index'))
    except ValueError:
        if name == '':
            return redirect(url_for('index'))
        pass
    allfiles = [name]
    allEvents = dataframeAll.EventType.unique()
    reports =    ['SourceDestEventFreq',
        'EventCount',
        'failedAuthentication',
        'SourceEventCount',
        'EventbySource',
        'activeSessions',
        'anonymousLogon',
        'MachineSessions',
        'userLogonFailure',
        'userlogonSummary',
        'policyScopeChange']

    return render_template('data.html',files=allfiles,Events=allEvents,reports=reports)

@app.route('/report/save/<file>/',methods=['GET'])
def getfile(file=None):
    try:
        if name =='' or dataframeAll == None:
            return redirect(url_for('index'))
    except ValueError:
        if name == '':
            return redirect(url_for('index'))
        pass
    response = make_response(dt.generatereport(file,dataframeAll).dropna(1,how='all').to_csv(index=False))
    cd = 'attachment; filename='+file+'.csv'
    response.headers['Content-Disposition'] = cd 
    response.mimetype='text/csv'
    return response

@app.route('/report/<report>')
def getreport(report=None):
    try:
        if name =='' or dataframeAll == None:
            return redirect(url_for('index'))
    except ValueError:
        if name == '':
            return redirect(url_for('index'))
        pass
    return dt.generatereport(report,dataframeAll).dropna(1,how='all').to_csv(index=False)

@app.route('/event/<event>',methods=['GET'])
def getevent(event=None):
    try:
        if name =='' or dataframeAll == None:
            return redirect(url_for('index'))
    except ValueError:
        if name == '':
            return redirect(url_for('index'))
        pass
    return dt.GetEvent(dataframeAll,event).dropna(1,how='all').to_csv(index=False)

@app.route('/event/save/<event>',methods=['GET'])
def saveevent(event=None):
    try:
        if name =='' or dataframeAll == None:
            return redirect(url_for('index'))
    except ValueError:
        if name == '':
            return redirect(url_for('index'))
        pass
    response = make_response(dt.GetEvent(dataframeAll,event).dropna(1,how='all').to_csv(index=False))
    cd = 'attachment; filename='+event+'.csv'
    response.headers['Content-Disposition'] = cd 
    response.mimetype='text/csv'
    return response

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    global name
    global dataframeAll
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = filename.split('.')[0]
            path = 'Dataset\\'+filename
            unzip(file,filename)
            name=filename.split('.')[0]
            dataframeAll = (makecsv(path,filename)).iloc[1:,:] 
            shutil.rmtree(path)
            return redirect(url_for('index'))
    else:
        return '''
        <!doctype html>
        <title>Upload new zip File</title>
        <h1>Upload new csv.zip File</h1>
        <form method=post enctype=multipart/form-data>
        <input type=file name=file>
        <input type=submit value=Upload>
        </form>
        '''


if __name__ == '__main__':
    app.debug = True
    # Threaded option to enable multiple instances for multiple user access support
    app.run(host='0.0.0.0',threaded=True,port=5500)

    # Serve the app with gevent
    # http_server = WSGIServer(('0.0.0.0', 5500), app)
    # http_server.serve_forever()