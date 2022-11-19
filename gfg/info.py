import os 
EMAIL_USE_TLS = True 
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = "emailtesting437@gmail.com"
EMAIL_HOST_PASSWORD = os.environ.get('PYTHON_PASS')
EMAIL_PORT =  587