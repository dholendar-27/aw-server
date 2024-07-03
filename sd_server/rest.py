import getpass
import os
import traceback
from functools import wraps
from threading import Lock
from typing import Dict
import sys
import pytz
import numpy as np
from tzlocal import get_localzone
from xhtml2pdf import pisa
from dateutil.parser import parse
from sd_core.launch_start import delete_launch_app, launch_app, check_startup_status, set_autostart_registry
from sd_core.util import authenticate, is_internet_connected, reset_user
import pandas as pd
from datetime import datetime, timedelta, date, time
import iso8601
from sd_core import schema, db_cache
from sd_core.models import Event
from sd_core.cache import *
from sd_query.exceptions import QueryException
from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    request,
)
from flask_restx import Api, Resource, fields
import jwt
from io import BytesIO
from . import logger
from .api import ServerAPI
from .exceptions import BadRequest, Unauthorized
from sd_qt.manager import Manager
from sd_datastore.storages.peewee import blocked_apps, blocked_url
import requests

application_cache_key = "application_cache"
manager = Manager()


def host_header_check(f):
    """
        Check if token is valid. This is a decorator for API methods that need to be decorated in order to check the token in the Host header

        @param f - function to be decorated with this

        @return tuple of ( token error
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        """
         Decorate to check token. This is a decorator that can be used as a context manager or in a class decorator.


         @return tuple of JSON response and status code. If status code is 0 it means success
        """
        excluded_paths = [
            '/api/0/buckets/',
            '/api/swagger.json',
        ]
        # This method is used to check if the request is valid and if the request is a heartbeat credentials and the request is not a valid credentials.
        if "/heartbeat" not in request.path and "/credentials" not in request.path and request.path not in excluded_paths and request.method != 'OPTIONS':
            token = request.headers.get("Authorization")
            # This method is used to validate the token.
            if not token:
                logging.warning("Token is missing")
                return {"message": "Token is missing"}, 401
            elif "/company" not in request.path:
                cache_key = "Sundial"
                cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
                if cached_credentials is not None:
                    user_key = cached_credentials.get("user_key")
                    try:
                        jwt.decode(token.replace("Bearer ", ""), key=user_key, algorithms=["HS256"])
                    except jwt.InvalidTokenError as e:
                        logging.error("Invalid token")
                        return {"message": "Invalid token"}, 401
                else:
                    user_key = None
                    logger.info("cache credentials are None at the time.system checking....please login")

        server_host = current_app.config["HOST"]
        req_host = request.headers.get("host", None)
        # Check if server is listening on 0. 0. 0. 0. 0. 0 host header check is disabled.
        if server_host == "0.0.0.0":
            logging.warning(
                "Server is listening on 0.0.0.0, host header check is disabled (potential security issue)."
            )
        elif req_host is None:
            return {"message": "host header is missing"}, 400
        elif req_host.split(":")[0] not in ["localhost", "127.0.0.1", server_host]:
            return {"message": f"host header is invalid (was {req_host})"}, 400

        return f(*args, **kwargs)

    return decorator


blueprint = Blueprint("api", __name__, url_prefix="/api")
api = Api(blueprint, doc="/", decorators=[host_header_check])

# Loads event and bucket schema from JSONSchema in sd_core
event = api.schema_model("Event", schema.get_json_schema("event"))
bucket = api.schema_model("Bucket", schema.get_json_schema("bucket"))
buckets_export = api.schema_model("Export", schema.get_json_schema("export"))

# TODO: Construct all the models from JSONSchema?
#       A downside to contructing from JSONSchema: flask-restplus does not have marshalling support

info = api.model(
    "Info",
    {
        "hostname": fields.String(),
        "version": fields.String(),
        "testing": fields.Boolean(),
        "device_id": fields.String(),
    },
)

create_bucket = api.model(
    "CreateBucket",
    {
        "client": fields.String(required=True),
        "type": fields.String(required=True),
        "hostname": fields.String(required=True),
    },
)

update_bucket = api.model(
    "UpdateBucket",
    {
        "client": fields.String(required=False),
        "type": fields.String(required=False),
        "hostname": fields.String(required=False),
        "data": fields.String(required=False),
    },
)


# Decorator

def copy_doc(api_method):
    """
     Copy docstrings from another function to the decorated function. Used to copy docstrings in ServerAPI over to the flask - restplus Resources.

     @param api_method - The method to copy the docstrings from.

     @return A decorator that copies the docstrings from the decorated function
    """
    """Decorator that copies another functions docstring to the decorated function.
    Used to copy the docstrings in ServerAPI over to the flask-restplus Resources.
    (The copied docstrings are then used by flask-restplus/swagger)"""

    def decorator(f):
        """
         Decorate a function to add documentation. This is useful for methods that are decorated with @api_method

         @param f - The function to decorate.

         @return The decorated function as a decorator ( not a decorator
        """
        f.__doc__ = api_method.__doc__
        return f

    return decorator


@api.route("/0/info")
class InfoResource(Resource):
    @api.doc(security="Bearer")
    @api.marshal_with(info)
    @copy_doc(ServerAPI.get_info)
    def get(self) -> Dict[str, Dict]:
        """
         Get information about the application. This is a shortcut for : meth : ` flask. api. get_info `.


         @return A dictionary of application information or an empty dictionary if there is no information
        """
        return current_app.api.get_info()


@api.route("/0/buckets/")
class BucketsResource(Resource):
    # TODO: Add response marshalling/validation
    @copy_doc(ServerAPI.get_buckets)
    def get(self) -> Dict[str, Dict]:
        """
         Get all buckets. This is a shortcut to : meth : ` ~flask. api. Baskets. get_buckets `.


         @return A dictionary of bucket names and their values keyed by bucket
        """
        return current_app.api.get_buckets()


@api.route("/0/buckets/<string:bucket_id>")
class BucketResource(Resource):
    @api.doc(model=bucket)
    @copy_doc(ServerAPI.get_bucket_metadata)
    def get(self, bucket_id):
        """
         Get metadata for a bucket. This is a GET request to the ` ` S3_bucket_metadata ` ` endpoint.

         @param bucket_id - the ID of the bucket to get metadata for

         @return a dict containing bucket metadata or None if not found
        """
        return current_app.api.get_bucket_metadata(bucket_id)

    @api.expect(create_bucket)
    @copy_doc(ServerAPI.create_bucket)
    def post(self, bucket_id):
        """
         Create a bucket. This endpoint requires authentication and will return a 204 if the bucket was created or a 304 if it already exists.

         @param bucket_id - the id of the bucket to create

         @return http code 200 if bucket was created 304 if it
        """
        data = request.get_json()
        bucket_created = current_app.api.create_bucket(
            bucket_id,
            event_type=data["type"],
            client=data["client"],
            hostname=data["hostname"],
        )
        # Returns a 200 if bucket was created
        if bucket_created:
            return {}, 200
        else:
            return {}, 304

    @api.expect(update_bucket)
    @copy_doc(ServerAPI.update_bucket)
    def put(self, bucket_id):
        """
         Update a bucket. This endpoint is used to update an existing bucket. The request must be made with a JSON object in the body and the data field will be updated to the new data.

         @param bucket_id - the ID of the bucket to update

         @return a 200 response with the updated bucket or an error
        """
        data = request.get_json()
        current_app.api.update_bucket(
            bucket_id,
            event_type=data["type"],
            client=data["client"],
            hostname=data["hostname"],
            data=data["data"],
        )
        return {}, 200

    @copy_doc(ServerAPI.delete_bucket)
    @api.param("force", "Needs to be =1 to delete a bucket it non-testing mode")
    def delete(self, bucket_id):
        """
         Delete a bucket. Only allowed if sd - server is running in testing mode

         @param bucket_id - ID of bucket to delete

         @return 200 if successful 404 if not ( or on error
        """
        args = request.args
        # DeleteBucketUnauthorized if sd server is running in testing mode or if sd server is running in testing mode or if force 1
        if not current_app.api.testing:
            # DeleteBucketUnauthorized if sd server is running in testing mode or if force 1
            if "force" not in args or args["force"] != "1":
                msg = "Deleting buckets is only permitted if sd-server is running in testing mode or if ?force=1"
                raise Unauthorized("DeleteBucketUnauthorized", msg)

        current_app.api.delete_bucket(bucket_id)
        return {}, 200


# EVENTS

@api.route("/0/buckets/<string:bucket_id>/events")
class EventsResource(Resource):
    # For some reason this doesn't work with the JSONSchema variant
    # Marshalling doesn't work with JSONSchema events
    # @api.marshal_list_with(event)
    @api.doc(model=event)
    @api.param("limit", "the maximum number of requests to get")
    @api.param("start", "Start date of events")
    @api.param("end", "End date of events")
    @copy_doc(ServerAPI.get_events)
    def get(self, bucket_id):
        """
         Get events for a bucket. This endpoint is used to retrieve events that have occurred since the last call to : func : ` ~flask. api. Bucket. create `.

         @param bucket_id - the bucket to get events for.

         @return 200 OK with events in JSON. Example request **. : http Example response **. :
        """
        args = request.args
        limit = int(args["limit"]) if "limit" in args else -1
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_events(
            bucket_id, limit=limit, start=start, end=end
        )
        return events, 200

    # TODO: How to tell expect that it could be a list of events? Until then we can't use validate.
    @api.expect(event)
    @copy_doc(ServerAPI.create_events)
    def post(self, bucket_id):
        """
         Create events in a bucket. This endpoint is used to create one or more events in a bucket.

         @param bucket_id - ID of bucket to create events in

         @return JSON representation of the created event or HTTP status code
        """
        data = request.get_json()
        logger.debug(
            "Received post request for event in bucket '{}' and data: {}".format(
                bucket_id, data
            )
        )

        # Convert a POST data to a list of events.
        if isinstance(data, dict):
            events = [Event(**data)]
        elif isinstance(data, list):
            events = [Event(**e) for e in data]
        else:
            raise BadRequest("Invalid POST data", "")

        event = current_app.api.create_events(bucket_id, events)
        return event.to_json_dict() if event else None, 200


@api.route("/0/buckets/<string:bucket_id>/events/count")
class EventCountResource(Resource):
    @api.doc(model=fields.Integer)
    @api.param("start", "Start date of eventcount")
    @api.param("end", "End date of eventcount")
    @copy_doc(ServerAPI.get_eventcount)
    def get(self, bucket_id):
        args = request.args
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_eventcount(bucket_id, start=start, end=end)
        return events, 200


@api.route("/0/buckets/<string:bucket_id>/events/<int:event_id>")
class EventResource(Resource):
    @api.doc(model=event)
    @copy_doc(ServerAPI.get_event)
    def get(self, bucket_id: str, event_id: int):
        """
         Get an event by bucket and event id. This is an endpoint for GET requests that need to be handled by the client.

         @param bucket_id - ID of the bucket containing the event
         @param event_id - ID of the event to retrieve

         @return A tuple of HTTP status code and the event if
        """
        logger.debug(
            f"Received get request for event with id '{event_id}' in bucket '{bucket_id}'"
        )
        event = current_app.api.get_event(bucket_id, event_id)
        # Return event and response code
        if event:
            return event, 200
        else:
            return None, 404


@api.route("/0/buckets/<string:bucket_id>/heartbeat")
class HeartbeatResource(Resource):
    def __init__(self, *args, **kwargs):
        """
         Initialize the object. This is the first thing to do before the object is created
        """
        self.lock = Lock()
        super().__init__(*args, **kwargs)

    @api.expect(event, validate=True)
    @api.param(
        "pulsetime", "Largest timewindow allowed between heartbeats for them to merge"
    )
    @copy_doc(ServerAPI.heartbeat)
    def post(self, bucket_id):
        """
        Sends a heartbeat to Sundial. This is an endpoint that can be used to check if an event is active and if it is the case.
        @param bucket_id - The ID of the bucket to send the heartbeat to.
        @return 200 OK if heartbeats were sent 400 Bad Request if there is no credentials in
        """
        heartbeat_data = request.get_json()
        if heartbeat_data['data']['title'] == '':
            heartbeat_data['data']['title'] = heartbeat_data['data']['app']

        if heartbeat_data['data']['app'] in ['ApplicationFrameHost.exe']:
            heartbeat_data['data']['app'] = heartbeat_data['data']['title'] + '.exe'

        # Set default title using the value of 'app' attribute if it's not present in the data dictionary
        settings = db_cache.retrieve("settings_cache")
        if not settings:
            db_cache.store("settings_cache", current_app.api.retrieve_all_settings())
        settings_code = settings.get("weekdays_schedule", {})
        schedule = settings.get("schedule", {})

        true_week_values = [key.lower() for key, value in settings_code.items() if value is True]

        if settings_code.get("starttime") and settings_code.get("endtime"):
            try:
                start_time_str = settings_code.get("starttime")
                end_time_str = settings_code.get("endtime")

                s_time_obj = datetime.strptime(start_time_str, "%I:%M %p")
                e_time_obj = datetime.strptime(end_time_str, "%I:%M %p")

                local_start_time = s_time_obj.strftime("%H:%M")
                local_end_time = e_time_obj.strftime("%H:%M")

                # local_start_time_str = "17:57"
                # Get the current date
                current_date = datetime.now().date()
                day_name = current_date.strftime("%A")
                # Parse the time string and create a datetime object with the current date
                local_start_time = datetime.strptime(f"{current_date} {local_start_time}", "%Y-%m-%d %H:%M")
                local_end_time = datetime.strptime(f"{current_date} {local_end_time}", "%Y-%m-%d %H:%M")

                # Now local_start_time is a datetime object, you can use astimezone method
                start_utc_time = local_start_time.astimezone(pytz.utc)
                end_utc_time = local_end_time.astimezone(pytz.utc)
            except json.JSONDecodeError:
                logger.info("Error: Failed to decode JSON string")

        # Check if schedule is true and contains weekdays
        current_time_utc = datetime.now(pytz.utc)
        if schedule and (day_name.lower() in true_week_values) and not (
                start_utc_time <= current_time_utc <= end_utc_time):
            return {"message": "Skipping data capture."}, 200
            # Capture data
        heartbeat = Event(**heartbeat_data)

        cache_key = "Sundial"
        cached_credentials = cache_user_credentials(cache_key, "SD_KEYS")
        # Returns cached credentials if cached credentials are not cached.
        if cached_credentials is None:
            return {"message": "No cached credentials."}, 400

        # The pulsetime parameter is required.
        pulsetime = float(request.args["pulsetime"]) if "pulsetime" in request.args else None
        if pulsetime is None:
            return {"message": "Missing required parameter pulsetime"}, 400

        # This lock is meant to ensure that only one heartbeat is processed at a time,
        # as the heartbeat function is not thread-safe.
        # This should maybe be moved into the api.py file instead (but would be very messy).
        if not self.lock.acquire(timeout=1):
            logger.warning(
                "Heartbeat lock could not be acquired within a reasonable time, this likely indicates a bug."
            )
            return {"message": "Failed to acquire heartbeat lock."}, 500
        try:
            event = current_app.api.heartbeat(bucket_id, heartbeat, pulsetime)
        finally:
            self.lock.release()

        if event:
            return event.to_json_dict(), 200
        elif not event:
            return "event not occured"
        else:
            return {"message": "Heartbeat failed."}, 500
