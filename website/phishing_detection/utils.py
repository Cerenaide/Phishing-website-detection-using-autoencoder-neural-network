from keras.models import load_model
import joblib
import requests
import pickle
import numpy as np
from bs4 import BeautifulSoup
#Packages required for Address Bar feature extraction
from urllib.parse import urlparse, urlencode
import ipaddress
import re
#Checks for IP address in URL
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip
#Checks if '@' symbol is in the URL
def haveAtSign(url):
    if url is None:
        return False
    if "@" in url:
        at = 1
    else:
        at = 0
    return at

#Checks the length of the URL
def  getLength(url):
    if url is None:
        return False
    if len(url) > 54:
        length = 1
    else:
        length = 0
    return length
#Acquires the depth of the URl
from urllib.parse import urlparse

def getDepth(url):
    if url is None:
        return 0
    s = urlparse(str(url)).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth += 1
    return depth

#Checks for redirection "//" in the URL
def redirection(url):
    if url is None:
        return 0
    position = url.rfind('//')
    if position > 6:
        if position > 7:
            return 1
        else:
            return 0
    else:
        return 0

#Checks if the "HTTPS" token is present in the domain name

def httpDomain(url):
    domain = urlparse(url).netloc
    if isinstance(domain, bytes):
        domain = domain.decode('utf-8')
    if 'https' in domain:
        return 1
    else:
        return 0


#List of the shortening services available
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
#Checks for the shortening services in the URL
def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0
#Checks for prefix or suffix separated by a dash symbol
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1
    else:
        return 0
#Importing packages for implementing HTML and Javascript based features
import requests
#Checking for IFrame redirection
def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[|]", response.text):
            return 0
        else: 
            return 1
#Checking for status bar customization by searching for mouseOver event
def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("", response.text):
            return 1
        else:
            return 0
#Checks the status of right click attribute
def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1
#Checks if the redirection of site is less than one
def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1
# Import required libraries
import pickle
import numpy as np
from urllib.parse import urlparse
import requests

# Load the saved autoencoder model
model_path = 'C:\\Users\\Josh\\website\\phishing_detection\\models\\model.h5'
autoencoder = load_model(model_path)

# Define the feature extraction function
def featureExtraction(url):
    features = []
    #Address bar feature extraction (9)
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    #HTML and Javascript based features(4)
    try:
        response = requests.get(url)
    except:
        response = ""
    
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))
        
    return features

# Define a function to preprocess the website URL and create features for the autoencoder model
def preprocess_website(url):
    input_vector = np.array(featureExtraction(url))
    return input_vector

def classify_website(url):
    # Preprocess the website URL
    input_vector = preprocess_website(url)

    # Use the saved autoencoder model to classify the website
    reconstructed_vector = autoencoder.predict(input_vector.reshape(1,-1))
    mse = np.mean(np.power(input_vector - reconstructed_vector, 2), axis=1)
    threshold = 0.2 # Adjust the threshold as needed
    is_phishing = mse > threshold

    return is_phishing

def classifier(is_phishing):
    if is_phishing:
        return 'Phishing website'
    else:
        return 'Legitimate website'
