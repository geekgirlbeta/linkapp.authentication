import pika
import json
import strict_rfc3339

import time
import atexit

class TooManyRetries(Exception):
    """
    Link Messenger has tried to reconnect to the message queue too many times.
    """

class AuthenticationMessenger:
    
    def __init__(self, url, max_retries=10, retry_sleep_start=0.1):
        self.url = url
        self.retries = 1
        self.max_retries = max_retries
        self.retry_sleep_start = retry_sleep_start
        
        self.connect()
        atexit.register(self.disconnect)
        
        

        
    def wait(self):
        """
        Returns the next amount of time to wait until retrying a failed 
        operation.
        """
        return self.retry_sleep_start*(self.retries**2)
        
        
    def publish(self, channel, *args, **kwargs):
        try:
            if channel == "job":
                self.job_channel.basic_publish(*args, **kwargs)
            elif channel == "log":
                self.log_channel.basic_publish(*args, **kwargs)
        except pika.exceptions.ConnectionClosed:
            print("Reconnecting")
            self.connect()
            self.publish(channel, *args, **kwargs)

    def connect(self):
        if self.retries >= self.max_retries:
            raise TooManyRetries("Maximum retries of {} exceeded".format(self.retries))
        
        try:
            self.connection = pika.BlockingConnection(pika.URLParameters(self.url))
            
            self.job_channel = self.connection.channel()
            self.job_channel.queue_declare(queue='auth_jobs', durable=True)
            
            self.log_channel = self.connection.channel()
            self.log_channel.exchange_declare(exchange='auth_logs',type='fanout')
            self.retries = 0
            
        except pika.exceptions.ConnectionClosed:
            print("Reconnecting, waiting {} seconds (retries: {})".format(self.wait(), self.retries))
            time.sleep(self.wait())
            self.retries += 1
            self.connect()
            
    
    def disconnect(self):
        self.connection.close()
    
        
    def job(self, message):
        self.publish("job", 
            exchange='',
            routing_key='auth_jobs',
            body=json.dumps(message),
            properties=pika.BasicProperties(
               delivery_mode = 2, # make message persistent
        ))
        
        
        
    def log(self, message):
        message["time"] = strict_rfc3339.now_to_rfc3339_utcoffset()
        
        self.publish("log", 
            exchange='auth_logs',
            routing_key='',
            body=json.dumps(message))
        
    def exists(self, username, exists):
        message = {
            "username": username,
            "exists?": exists,
            "action": "user:exists"
        }
        
        self.log(message)
    
    def authorized(self, username, system):
        message = {
            "username": username,
            "system": system,
            "action": "user:authorized"
        }
        
        self.log(message)
    
    def failed(self, username, system):
        message = {
            "username": username,
            "system": system,
            "action": "user:failed-authorize"
        }
        
        self.log(message)
    
    def added(self, username):
        message = {
            "username": username,
            "action": "user:added"
        }
        
        self.log(message)
    
    def removed(self, username):
        message = {
            "username": username,
            "action": "user:removed"
        }
        
        self.log(message)
        
    def viewed_listing(self):
        message = {
            "action": "user:viewed-listing"
        }
        
        self.log(message)
        
    def viewed(self, username):
        message = {
            "username": username,
            "action": "user:viewed"
        }
        
        self.log(message)
        
    def viewed_field(self, username, *field):
        message = {
            "username": username,
            "field": field,
            "action": "user:viewed-field"
        }
        
        self.log(message)
        
    def changed(self, username, *field):
        message = {
            "username": username,
            "field": field,
            "action": "user:changed-field"
        }
        
        self.log(message)