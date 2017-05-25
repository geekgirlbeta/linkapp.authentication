"""
All requests must be made over SSL.

HTTP Basic Auth is in effect. Services must provide service account credentials 
to utilize this service.

/                     POST        add user
/                     GET         list users                     
/[user]               GET         get all fields for user (only provides 404 if user doesn't exist - no public profile data yet)
/[user]               DELETE      remove user
/[user]/[field]       GET         get field (password is not available)
/[user]/[field]       PUT         modify field (only password supported)
/[user]               POST        authenticate user
"""

from webob import Response, Request

from .manager import AuthenticationManager, UserAlreadyExists, BadUsername, FieldNotFound
from .queue import AuthenticationMessenger
import jsonschema
import base64
from urllib import parse

def bad_request(environ, start_response, msg="Bad Request", status=400):
    res = Response(msg, status=status)
    
    return res(environ, start_response)

class BadRequest(Exception):
    """
    Raised when something bad happened in a request
    """
    
    def __init__(self, msg="Bad Request", code=400):
        self.msg = msg
        self.code = code
        
    def __str__(self):
        return self.msg
        
        
    def __call__(self, environ, start_response):
        res = Response(self.msg, status=self.code)
        return res(environ, start_response)
    
class NotFound(BadRequest):
    """
    Raised when something is not found.
    """
    def __init__(self, msg="Not Found", code=404):
        BadRequest.__init__(self, msg, code)
    
class UnsupportedMediaType(BadRequest):
    """
    Raised when a bad content type is specified by the client.
    """
    def __init__(self, msg="Unsupported media type", code=415):
        BadRequest.__init__(self, msg, code)
        
class Unauthorized(BadRequest):
    """
    Raised when a bad content type is specified by the client.
    """
    def __init__(self, msg="Unauthorized", code=401, realm="Linkapp Microservices"):
        BadRequest.__init__(self, msg, code)
        self.realm = realm
        
    def __call__(self, environ, start_response):
        res = Response(self.msg, status=self.code)
        res.headers['www-authenticate'] = 'Basic realm={}'.format(self.realm)
        
        return res(environ, start_response)

class AuthenticationMicroservice:
    
    def __init__(self, config):
        self.config = config
        self.authentication_manager = AuthenticationManager(self.config.redis_url, self.config.rabbit_url)
        self.authentication_messenger = AuthenticationMessenger(self.config.rabbit_url)
    
    def authorize(self, req):
        if req.authorization:
            auth_type, hashed_pass = req.authorization
            
            decoded = base64.b64decode(hashed_pass)
            
            username, password = decoded.decode('utf-8').split(':')
            
            if not self.authentication_manager.authenticate(username, password, system=True):
                raise Unauthorized()
        else:
            raise Unauthorized()
    
    def __call__(self, environ, start_response):
        req = Request(environ, charset="utf8")
        
        new_path = parse.unquote(req.path)
        
        parts = req.path.split("/")[1:]
        
        try:
            if req.content_type != "application/json":
                raise UnsupportedMediaType()
                
            if parts == ['']:
                if req.method == 'GET':
                    result = self.list_users(req)
                elif req.method == 'POST':
                    result = self.add_user(req)
                else:
                    raise BadRequest()
            elif len(parts) == 1:
                username = parts[0]
                
                if req.method == 'GET':
                    result = self.get_user(req, username)
                elif req.method == 'POST':
                    result = self.authenticate_user(req, username)
                elif req.method == 'DELETE':
                    result = self.remove_user(req, username)
                else:
                    raise BadRequest()
            elif len(parts) == 2:
                username = parts[0]
                field = parts[1]
                
                if req.method == 'GET':
                    result = self.get_user_field(req, username, field)
                elif req.method == 'PUT':
                    result = self.modify_user_field(req, username, field)
                else:
                    raise BadRequest()
            else:
                raise BadRequest()
        except BadRequest as br:
            return br(environ, start_response)
        except ValueError as e:
            return bad_request(environ, start_response, str(e))
        except jsonschema.ValidationError as e:
           return bad_request(environ, start_response, e.message)
        except UserAlreadyExists:
            return bad_request(environ, start_response, "User already exists")
        except BadUsername:
            return bad_request(environ, start_response, "Username is invalid")
            
        res = Response()
        res.json = result
        return res(environ, start_response)
        
    def add_user(self, req):
        self.authorize(req)
        
        data = req.json
        
        return self.authentication_manager.add(**data)
    
    def remove_user(self, req, username):
        self.authorize(req)
        
        if not self.authentication_manager.exists(username):
            raise NotFound()
        
        return self.authentication_manager.delete(username)
    
    def authenticate_user(self, req, username):
        self.authorize(req)
        
        password = req.json
        
        if self.authentication_manager.authenticate(username, password):
            return True
        else:
            return False
    
    def list_users(self, req):
        return self.authentication_manager.list_users()
    
    def get_user(self, req, username):
        if not self.authentication_manager.exists(username):
            raise NotFound('User does not exist')
            
        return self.authentication_manager.get(username)
    
    def get_user_field(self, req, username, field):
        
        if not self.authentication_manager.exists(username):
            raise NotFound('User does not exist')
        
        try:
            result = self.authentication_manager.get_one_field(username, field)
            
            if result is None:
                raise FieldNotFound()
            else:
                return result
             
        except FieldNotFound:
            raise NotFound('Field does not exist')
    
    def modify_user_field(self, req, username, field):
        self.authorize(req)
        
        if not self.authentication_manager.exists(username):
            raise NotFound('User does not exist')
        
        data = req.json
        
        if 'username' in data:
            raise BadRequest("Cannot change username")
        
        return self.authentication_manager.modify(username=username, **data)