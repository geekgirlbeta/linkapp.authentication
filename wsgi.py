from linkapp.authentication.wsgi import AuthenticationMicroservice
from linkapp.authentication.config import AuthenticationConfig

config = AuthenticationConfig()

app = AuthenticationMicroservice(config)