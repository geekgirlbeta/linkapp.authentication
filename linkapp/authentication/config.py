import os

class MissingConfig(Exception):
    """
    Raised when configuration variable is not provided.
    """
    

class AuthenticationConfig:
    """
    Where all the information will be extracted for the environment.
    """
    
    def __init__(self, redis_url=None, 
                       rabbit_url=None, 
                       rabbit_retries=None, 
                       rabbit_retry_sleep=None, 
                       listing_per_page=None):
        
        if redis_url is None:
            from_environ = os.environ.get('LINKAPP_REDIS_URL', False)
            if from_environ is False:
                raise MissingConfig("redis_url was not provided to the constructor or set in LINKAPP_REDIS_URL environment variable")
            else:
                self.redis_url = from_environ
        else:
            self.redis_url = redis_url
        
        
        if rabbit_url is None:
            from_environ = os.environ.get('LINKAPP_RABBIT_URL', False)
            if from_environ is False:
                raise MissingConfig("rabbit_url was not provided to the constructor or set in LINKAPP_RABBIT_URL environment variable")
            else:
                self.rabbit_url = from_environ
        else:
            self.rabbit_url = rabbit_url
            
        
        if rabbit_retries is None:
            self.rabbit_retries = int(os.environ.get('LINKAPP_RABBIT_RETRIES', "10"))
        else:
            self.rabbit_retries = rabbit_retries
            
        if rabbit_retry_sleep is None:
            self.rabbit_retry_sleep = float(os.environ.get('LINKAPP_RABBIT_RETRY_SLEEP', "0.1"))
        else:
            self.rabbit_retry_sleep = rabbit_retry_sleep
            
        if listing_per_page is None:
            self.listing_per_page = int(os.environ.get('LINKAPP_LISTING_PER_PAGE', "10"))
        else:
            self.listing_per_page = listing_per_page

