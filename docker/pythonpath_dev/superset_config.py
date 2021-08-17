# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is included in the final Docker image and SHOULD be overridden when
# deploying the image to prod. Settings configured here are intended for use in local
# development environments. Also note that superset_config_docker.py is imported
# as a final step as a means to override "defaults" configured here
#
import logging
import os
import base64
from flask_appbuilder.security.manager import AUTH_OAUTH
from superset_patchup.oauth import CustomSecurityManager
from datetime import timedelta
from typing import Optional

from cachelib.file import FileSystemCache
from celery.schedules import crontab

logger = logging.getLogger()


def get_env_variable(var_name: str, default: Optional[str] = None) -> str:
    """Get the environment variable or raise exception."""
    try:
        return os.environ[var_name]
    except KeyError:
        if default is not None:
            return default
        else:
            error_msg = "The environment variable {} was missing, abort...".format(
                var_name
            )
            raise EnvironmentError(error_msg)


DATABASE_DIALECT = get_env_variable("DATABASE_DIALECT")
DATABASE_USER = get_env_variable("DATABASE_USER")
DATABASE_PASSWORD = get_env_variable("DATABASE_PASSWORD")
DATABASE_HOST = get_env_variable("DATABASE_HOST")
DATABASE_PORT = get_env_variable("DATABASE_PORT")
DATABASE_DB = get_env_variable("DATABASE_DB")

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = "%s://%s:%s@%s:%s/%s" % (
    DATABASE_DIALECT,
    DATABASE_USER,
    DATABASE_PASSWORD,
    DATABASE_HOST,
    DATABASE_PORT,
    DATABASE_DB,
)

REDIS_HOST = get_env_variable("REDIS_HOST")
REDIS_PORT = get_env_variable("REDIS_PORT")
REDIS_CELERY_DB = get_env_variable("REDIS_CELERY_DB", "0")
REDIS_RESULTS_DB = get_env_variable("REDIS_RESULTS_DB", "1")

RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")


class CeleryConfig(object):
    BROKER_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    CELERY_IMPORTS = ("superset.sql_lab", "superset.tasks")
    CELERY_RESULT_BACKEND = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    CELERYD_LOG_LEVEL = "DEBUG"
    CELERYD_PREFETCH_MULTIPLIER = 1
    CELERY_ACKS_LATE = False
    CELERYBEAT_SCHEDULE = {
        "reports.scheduler": {
            "task": "reports.scheduler",
            "schedule": crontab(minute="*", hour="*"),
        },
        "reports.prune_log": {
            "task": "reports.prune_log",
            "schedule": crontab(minute=10, hour=0),
        },
    }


CELERY_CONFIG = CeleryConfig

FEATURE_FLAGS = {"ALERT_REPORTS": True}
ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
WEBDRIVER_BASEURL = "http://superset:8088/"
# The base URL for the email report hyperlinks.
WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL

SQLLAB_CTAS_NO_LIMIT = True

#SUPERSET
#

def stringToBase64(s):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

SECRET_KEY='Yd9OFHQfcu'
OL_SUPERSET_USER='superset'
OL_SUPERSET_PASSWORD='changeme'
OL_BASE_URL='http://35.171.194.94'

AUTHORIZATION_HEADER_TOKEN = stringToBase64(
    '%s:%s' % (OL_SUPERSET_USER, OL_SUPERSET_PASSWORD))

AUTH_TYPE = AUTH_OAUTH
OAUTH_PROVIDERS = [
    {   'name':'openlmis',
        'token_key':'access_token', # Name of the token in the response of access_token_url
        'icon':'fa-sign-in',   # Icon for the provider
        'remote_app': {
            'client_id': OL_SUPERSET_USER,  # Client Id (Identify Superset application)
            'client_secret': OL_SUPERSET_PASSWORD, # Secret for this Client Id (Identify Superset application)
            'client_kwargs':{
                'scope': 'read write'               # Scope for the Authorization
            },
            'access_token_method':'POST',    # HTTP Method to call access_token_url
            'access_token_params':{        # Additional parameters for calls to access_token_url
                'scope':'read write'
            },
            'access_token_headers':{    # Additional headers for calls to access_token_url
                'Authorization': 'Basic %s' % AUTHORIZATION_HEADER_TOKEN
            },
            'api_base_url': '%s/api/oauth' % OL_BASE_URL,
            'access_token_url': '%s:80/api/oauth/token?grant_type=authorization_code' % OL_BASE_URL,
            'authorize_url': '%s/api/oauth/authorize?' % OL_BASE_URL
        }
        }
]


# The default user self registration role
# AUTH_USER_REGISTRATION_ROLE = "OLMIS_Gamma"

# Will allow user self registration
# AUTH_USER_REGISTRATION = True

# Map Authlib roles to superset roles
AUTH_ROLE_ADMIN = 'Admin'
AUTH_ROLE_PUBLIC = 'Public'

# Will allow user self registration, allowing to create Flask users from Authorized User
AUTH_USER_REGISTRATION = True

# The default user self registration role
AUTH_USER_REGISTRATION_ROLE = "Admin"

# Extract and use X-Forwarded-For/X-Forwarded-Proto headers?
ENABLE_PROXY_FIX = True

# Allow iFrame access from openLMIS running on localhost
HTTP_HEADERS = {'X-Frame-Options': 'allow-from %s' % OL_BASE_URL}

CUSTOM_SECURITY_MANAGER = CustomSecurityManager

#SESSION_COOKIE_HTTPONLY = False

#SESSION_COOKIE_SAMESITE = 'None'  # One of [None, 'Lax', 'Strict']
#SESSION_COOKIE_SECURE = True

ENABLE_CORS = True
CORS_OPTIONS = {
    'origins': '*',
    'supports_credentials': True
}

WTF_CSRF_ENABLED = True
#WTF_CSRF_CHECK_DEFAULT = False
WTF_CSRF_EXEMPT_LIST = ['custom_security_manager']
WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365

#SESSION_COOKIE_HTTPONLY = False
#SESSION_COOKIE_SECURE = False
#SESSION_COOKIE_SAMESITE = "None"

# Add custom roles
ADD_CUSTOM_ROLES = True
CUSTOM_ROLES = {'OLMIS_Gamma': {'all_datasource_access'}}

#
# Optionally import superset_config_docker.py (which will have been included on
# the PYTHONPATH) in order to allow for local settings to be overridden
#
try:
    import superset_config_docker
    from superset_config_docker import *  # noqa

    logger.info(
        f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
    )
except ImportError:
    logger.info("Using default Docker config...")


