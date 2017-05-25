import redis
from passlib.hash import pbkdf2_sha256
import jsonschema
import re

from .queue import AuthenticationMessenger

schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "password": {"type": "string"},
        "encrypted": {"type": "boolean", "default":False},
        "system": {"type": "boolean", "default":False}
    },
    'required': ['username',]
    
}

add_schema = schema.copy()
add_schema["required"] = ["username", "password"]

def pipeline_monkeypatch(self, transaction=True, shard_hint=None):
        """
        MONKEYPATCH: callbacks really should be a copy!
        """
        return redis.client.StrictPipeline(
            self.connection_pool,
            self.response_callbacks.copy(),
            transaction,
            shard_hint)

redis.StrictRedis.pipeline = pipeline_monkeypatch

class UserAlreadyExists(Exception):
    """
    Raised when adding a user with a username that is already taken.
    """
    
class UserNotFound(Exception):
    """
    Raised when a user is not in the database.
    """

class FieldNotFound(Exception):
    """
    Raised when field is not present for a user (or not available)
    """
    
class BadUsername(Exception):
    """
    Raised when invalid characters are provided for a username
    """

class AuthenticationManager:
    
    def __init__(self, redis_url="redis://localhost:6379/0", rabbit_url="amqp://localhost"):
        self.connection = redis.StrictRedis.from_url(redis_url, decode_responses=True)
        self.link_messenger = AuthenticationMessenger(rabbit_url)
    
    def key(self, username):
        return "user:{}".format(username)
    
    def encrypt(self, password):
        return pbkdf2_sha256.hash(password)
    
    def authenticate(self, username, password, system=False):
        user = self.get(username, safe=False)
        
        if user:
            if system and user['system'] != 'True':
                self.link_messenger.failed(username, user['system'])
                return False
            
            self.link_messenger.authorized(username, user['system'])
            return pbkdf2_sha256.verify(password, user['password'])
        else:
            self.link_messenger.failed(username, None)
            return False
    
    def validate_username(self, username):
        match = re.match("^[\x00-\x7F/]+$", username)
        
        if match:
            return True
        else:
            return False
    
    def add(self, **kwargs):
        jsonschema.validate(kwargs, add_schema)
        
        if not self.validate_username(kwargs['username']):
            raise BadUsername()
        
        if self.exists(kwargs['username']):
            raise UserAlreadyExists()
        
        key = self.key(kwargs['username'])
        
        if not kwargs.get('encrypted', add_schema['properties']['encrypted']['default']):
            kwargs['password'] = self.encrypt(kwargs['password'])
            
        if 'encrypted' in kwargs:
            del kwargs['encrypted']
        
        kwargs['system'] = kwargs.get('system', add_schema['properties']['system']['default'])
        
        self.connection.hmset(key, kwargs)
        
        self.link_messenger.added(kwargs['username'])
        
        return kwargs['username']
    
    def modify(self, **kwargs):
        jsonschema.validate(kwargs, schema)
        
        if not kwargs.get('encrypted', add_schema['properties']['encrypted']['default']):
            kwargs['password'] = self.encrypt(kwargs['password'])
        
        if 'encrypted' in kwargs:
            del kwargs['encrypted']
        
        username = kwargs['username']
        del kwargs['username']
        
        result = self.connection.hmset(self.key(username), kwargs)
        
        self.link_messenger.changed(username, *kwargs.keys())
        
        return result
    
    def delete(self, username):
        result = self.connection.delete(self.key(username))
        
        return result
    
    def exists(self, username):
       key = self.key(username)
       exists = bool(self.connection.exists(key))
       
       self.link_messenger.exists(username, exists)
       
       return exists
    
    def get_one_field(self, username, field):
        if field in ['password']:
            raise FieldNotFound()
            
        result = self.connection.hmget(self.key(username), field)
        
        self.link_messenger.viewed_field(username, field)
        
        return result
            
    def _safe_user(self, response, **options):
        # SUPER CHEEKY
        it = iter(response)
        result = dict(zip(it, it))
        
        result['password'] = None
        
        return result
    
    def get(self, username, safe=True):
        with self.connection.pipeline() as pipe:
            if safe:
                pipe.set_response_callback('HGETALL', self._safe_user)
            
            pipe.hgetall(self.key(username))
            
            result = pipe.execute()
            
        self.link_messenger.viewed(username)
        return result[0]
        
    def list_users(self, safe=True):
        keys = self.connection.keys("user:*")
        with self.connection.pipeline() as pipe:
            if safe:
                pipe.set_response_callback('HGETALL', self._safe_user)
            
            for key in keys:
                pipe.hgetall(key)
                
            result = pipe.execute()
                
        self.link_messenger.viewed_listing()
                
        return result