import functools
from itertools import groupby
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from socket import gethostname
import threading
import time

from aw_core.cache import cache_user_credentials
from aw_core.cache import *
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Union,
)
from uuid import uuid4
from aw_core.util import decrypt_uuid, encrypt_uuid, load_key

import iso8601
from aw_core.dirs import get_data_dir
from aw_core.log import get_log_file_path
from aw_core.models import Event
from aw_query import query2
from aw_transform import heartbeat_merge
import keyring
import pytz

from .__about__ import __version__
from .exceptions import NotFound
import requests as req
from dateutil import parser

logger = logging.getLogger(__name__)

def get_device_id() -> str:
    path = Path(get_data_dir("aw-server")) / "device_id"
    if path.exists():
        with open(path) as f:
            return f.read()
    else:
        uuid = str(uuid4())
        with open(path, "w") as f:
            f.write(uuid)
        return uuid


def check_bucket_exists(f):
    @functools.wraps(f)
    def g(self, bucket_id, *args, **kwargs):
        if bucket_id not in self.db.buckets():
            raise NotFound("NoSuchBucket", f"There's no bucket named {bucket_id}")
        return f(self, bucket_id, *args, **kwargs)

    return g

def always_raise_for_request_errors(f: Callable[..., req.Response]):
    @functools.wraps(f)
    def g(*args, **kwargs):
        r = f(*args, **kwargs)
        try:
            r.raise_for_status()
        except req.RequestException as e:
            _log_request_exception(e)
            raise e
        return r

    return g

def _log_request_exception(e: req.RequestException):
    r = e.response
    logger.warning(str(e))
    try:
        d = r.json()
        logger.warning(f"Error message received: {d}")
    except json.JSONDecodeError:
        pass

class ServerAPI:
    def __init__(self, db, testing) -> None:
        """
         Initialize the Sundial instance. This is the method that must be called by the user to initialize the Sundial instance

         @param db - Database instance to use for communication
         @param testing - True if we are testing False otherwise.

         @return A boolean indicating success or failure of the initialization. If True the instance will be initialized
        """
        cache_key = "sundial"
        cache_user_credentials(cache_key,"SD_KEYS")
        self.db = db
        self.testing = testing
        self.last_event = {}  # type: dict
        self.server_address = "{protocol}://{host}:{port}".format(
            protocol='http', host='14.97.160.178', port='9010'
        )
        self.ralvie_server_queue = RalvieServerQueue(self)

    def save_settings(self, settings_id, settings_dict) -> None:
        """
         Save settings to the database. This is a low - level method for use by plugins that want to save settings to the database as part of their initialization and / or reinitialization.

         @param settings_id - ID of the settings to save.
         @param settings_dict - Dictionary of settings to save. Keys must match the names of the settings in the dictionary.

         @return True if successful False otherwise. Raises : py : exc : ` ~sqlalchemy. exc. IntegrityError ` if there is a problem
        """
        self.db.save_settings(settings_id=settings_id, settings_dict=settings_dict)

    def get_settings(self, settings_id) -> Dict[str, Any]:
        """
         Retrieve settings from the database. This is a low - level method to be used by plugins that want to retrieve settings from the database.

         @param settings_id - ID of the settings to retrieve.

         @return Dictionary of settings. Keys are the names of the settings
        """
        return self.db.retrieve_settings(settings_id)

    def _url(self, endpoint: str):
        """
         Generate URL for an API. This is used to generate the URL that will be used to access the API.

         @param endpoint - The endpoint to access. Must be prefixed with the server address e. g.

         @return The URL to access the API with the given endpoint
        """
        return f"{self.server_address}{endpoint}"

    @always_raise_for_request_errors
    def _get(self, endpoint: str, params: Optional[dict] = None) -> req.Response:
        """
         Make a GET request to Cerebrum and return the response. This is a helper for _get_url and _get_url_with_params

         @param endpoint - The endpoint to call e. g.
         @param params - A dictionary of key / value pairs to include in the request

         @return A : class : ` Response `
        """
        headers = {"Content-type": "application/json", "charset": "utf-8"}
        # Update the headers with the params.
        if params:
            headers.update(params)
        return req.get(self._url(endpoint), headers=headers)

    @always_raise_for_request_errors
    def _post(

        self,
        endpoint: str,
        data: Union[List[Any], Dict[str, Any]],
        params: Optional[dict] = None,
    ) -> req.Response:
        """
         Send a POST request to the API. This is a helper for : meth : ` _url ` to make it easier to use in conjunction with

         @param endpoint - The endpoint to send the request to.
         @param data - The data to send as the body of the request.
         @param params - A dictionary of headers to add to the request.

         @return The response from the request as a : class : ` req. Response `
        """
        headers = {"Content-type": "application/json", "charset": "utf-8"}
        # Update the headers with the params.
        if params:
            headers.update(params)
        return req.post(
            self._url(endpoint),
            data=bytes(json.dumps(data), "utf8"),
            headers=headers,
            params=params,
        )

    @always_raise_for_request_errors
    def _delete(self, endpoint: str, data: Any = dict()) -> req.Response:
        """
         Send a DELETE request to Cobbler. This is a helper method for : meth : ` delete_and_recover `.

         @param endpoint - The endpoint to send the request to. E. g.
         @param data - The data to send as the body of the request.

         @return A : class : ` req. Response ` object
        """
        headers = {"Content-type": "application/json"}
        return req.delete(self._url(endpoint), data=json.dumps(data), headers=headers)


    def init_db(self) -> bool:
        """
         Initialize the database. This is called after the connection has been established and all tables have been loaded.


         @return True if successful False if not ( in which case the database is in an error state
        """
        return self.db.init_db()

    def create_user(self, user:Dict[str, Any]):
        """
         Create a user on behalf of the authenticated user. This is a POST request to the ` ` / web / user ` ` endpoint.

         @param user - A dictionary containing the information to create the user on behalf of.

         @return The response from the server that was received as part of the request
        """
        endpoint = f"/web/user"
        return self._post(endpoint , user)

    def authorize(self, user:Dict[str, Any]):
        """
         Authorize a user. This is a POST request to the ` / web / user / authorize ` endpoint.

         @param user - The user to authorize. See API docs for more information.

         @return The response from the server. If there was an error the response will contain the error
        """
        endpoint = f"/web/user/authorize"
        return self._post(endpoint , user)

    def create_company(self, user:Dict[str, Any], token):
        """
         Create a company for the user. This is a POST request to the ` / web / company ` endpoint.

         @param user - Dictionary containing the user's data. See example below.
         @param token - Authorization token to use for this request. See example below.

         @return A response from the server that contains the company ID
        """
        endpoint = f"/web/company"
        return self._post(endpoint , user, {"Authorization" : token})

    def sync_events_to_ralvie(self):
        try:
            userId = load_key("userId")
            if not userId:
                time.sleep(300)
            utc_now = datetime.utcnow()
            utc_now = utc_now.replace(tzinfo=pytz.utc)

            # Calculate start time (20 minutes less than current UTC time)
            start_time = utc_now - timedelta(minutes=5)

            # Calculate end time (10 minutes less than current UTC time)
            end_time = utc_now
            data = self.get_dashboard_events(start_time, end_time)
            if(data and data["events"] and userId):
                print("total events: ",len(data["events"]))
                payload = {"userId" : userId, "events" : data["events"]}
                endpoint = f"/web/event"
                self._post(endpoint , payload)
            time.sleep(300)
        except Exception as e:
            print(e)

    def get_user_credentials(self, userId, token):
        """
        Get credentials for a user. This is a wrapper around the get_credentials endpoint to provide access to the user '

        @param userId
        @param token
        """

        cache_key = "sundial"
        endpoint = f"/web/user/{userId}/credentials"
        user_credentials = self._get(endpoint, {"Authorization": token})

        # This function is used to retrieve the user credentials.
        if user_credentials.status_code == 200 and json.loads(user_credentials.text)["code"] == 'RCI0000':
            credentials_data = json.loads(user_credentials.text)["data"]["credentials"]
            user_data = json.loads(user_credentials.text)["data"]["user"]

            db_key = credentials_data["dbKey"]
            data_encryption_key = credentials_data["dataEncryptionKey"]
            user_key = credentials_data["userKey"]
            email = user_data["email"]
            phone = user_data["phone"]
            firstName = user_data['firstName']
            lastName = user_data['lastName']
            key = user_key
            encrypted_db_key = encrypt_uuid(db_key, key)
            encrypted_data_encryption_key = encrypt_uuid(data_encryption_key, key)
            encrypted_user_key = encrypt_uuid(user_key, key)

            SD_KEYS = {
                "user_key": user_key,
                "encrypted_db_key": encrypted_db_key,
                "encrypted_data_encryption_key": encrypted_data_encryption_key,
                "email": email,
                "phone": phone,
                "firstname": firstName,
                "lastname": lastName,
                "userId": userId,
            }

            store_credentials(cache_key, SD_KEYS)
            serialized_data = json.dumps(SD_KEYS)
            add_password("SD_KEYS", serialized_data)

            cached_credentials = get_credentials(cache_key)
            key_decoded = cached_credentials.get("user_key")

            decrypted_db_key = decrypt_uuid(encrypted_db_key, key_decoded)
            decrypted_user_key = decrypt_uuid(encrypted_user_key, key_decoded)
            decrypted_data_encryption_key = decrypt_uuid(encrypted_data_encryption_key, key_decoded)
            self.last_event = {}

            print(f"user_key: {decrypted_user_key}")
            print(f"db_key: {decrypted_db_key}")
            print(f"watcher_key: {decrypted_data_encryption_key}")

        return user_credentials

    def get_user_details(self):
        """
         Get details of user. This is used to populate the sundial page in the admin.


         @return Dictionary that contains email phone firstname and lastname
        """
        cache_key = "sundial"
        cached_credentials = get_credentials(cache_key)
        settings_id = 1
        image = self.db.retrieve_settings(settings_id)
        response_data = {"email": cached_credentials.get("email"), "phone": cached_credentials.get("phone"),
                         "firstname": cached_credentials.get("firstname"),
                         "lastname": cached_credentials.get("lastname")}
        # Set the image s profile image
        if image:
            response_data['ProfileImage'] = image['ProfileImage']
        else:
            response_data['ProfileImage'] = ""
        # Return cached credentials if cached credentials are not None.
        if not cached_credentials is None:
            return response_data


    def get_info(self) -> Dict[str, Any]:
        """
         Get information about the server. This is a dictionary that can be sent to the server to update the configuration.


         @return A dictionary that can be sent to the server to update
        """
        """Get server info"""
        payload = {
            "hostname": gethostname(),
            "version": __version__,
            "testing": self.testing,
            "device_id": get_device_id(),
        }
        return payload

    def get_buckets(self) -> Dict[str, Dict]:
        """
         Get all buckets from the database and add last_updated field to each bucket


         @return Dictionary of all buckets in the database with keys :
        """
        """Get dict {bucket_name: Bucket} of all buckets"""
        logger.debug("Received get request for buckets")
        buckets = self.db.buckets()
        # Update the last_updated timestamp and duration of each bucket
        for b in buckets:
            # TODO: Move this code to aw-core?
            last_events = self.db[b].get(limit=1)
            # Update the last_updated timestamp and duration of last_event.
            if len(last_events) > 0:
                last_event = last_events[0]
                last_updated = last_event.timestamp + last_event.duration
                buckets[b]["last_updated"] = last_updated.isoformat()
        return buckets

    @check_bucket_exists
    def get_bucket_metadata(self, bucket_id: str) -> Dict[str, Any]:
        """
         Get metadata about a bucket. This is a wrapper around the Bucket. metadata method

         @param bucket_id - The ID of the bucket to retrieve metadata about

         @return A dictionary of key / value
        """
        """Get metadata about bucket."""
        bucket = self.db[bucket_id]
        return bucket.metadata()

    @check_bucket_exists
    def export_bucket(self, bucket_id: str) -> Dict[str, Any]:
        """
         Export a bucket to a dataformat consistent across versions including all events. This is useful for exporting data that is in an unusual format such as JSON or JSON - serialized data.

         @param bucket_id - The ID of the bucket to export.

         @return The metadata associated with the bucket as a dictionary with keys ` events ` and ` dataformat `
        """
        """Export a bucket to a dataformat consistent across versions, including all events in it."""
        bucket = self.get_bucket_metadata(bucket_id)
        bucket["events"] = self.get_events(bucket_id, limit=-1)
        # Scrub event IDs
        # for event in bucket["events"]:
        #     del event["id"]
        return bucket

    def export_all(self) -> Dict[str, Any]:
        """
         Exports all buckets and their events to a format consistent across versions. This is useful for exporting a set of data that is stored in Amazon S3 and can be used to make sure they are in the correct format


         @return Dictionary of exported buckets
        """
        """Exports all buckets and their events to a format consistent across versions"""
        buckets = self.get_buckets()
        exported_buckets = {}
        # Export the bucket for the current window.
        for key, value in buckets.items():
            # Export the bucket for the given client.
            if value["client"] == "aw-watcher-window":
                id_of_client = value["id"]
                exported_buckets[id_of_client] = self.export_bucket(id_of_client)
        return exported_buckets

    def import_bucket(self, bucket_data: Any):
        """
         Import a bucket into the database. This is a wrapper around db. create_bucket to allow us to pass in bucket_data as a dict instead of a json object.

         @param bucket_data - The data to import into the database
        """
        bucket_id = bucket_data["id"]
        logger.info(f"Importing bucket {bucket_id}")

        # TODO: Check that bucket doesn't already exist
        self.db.create_bucket(
            bucket_id,
            type=bucket_data["type"],
            client=bucket_data["client"],
            hostname=bucket_data["hostname"],
            created=(
                bucket_data["created"]
                if isinstance(bucket_data["created"], datetime)
                else iso8601.parse_date(bucket_data["created"])
            ),
        )

        # scrub IDs from events
        # (otherwise causes weird bugs with no events seemingly imported when importing events exported from aw-server-rust, which contains IDs)
        for event in bucket_data["events"]:
            if "id" in event:
                del event["id"]

        self.create_events(
            bucket_id,
            [Event(**e) if isinstance(e, dict) else e for e in bucket_data["events"]],
        )

    def import_all(self, buckets: Dict[str, Any]):
        """
         Import all buckets into the storage. This is a no - op if there are no buckets to import

         @param buckets - A dictionary of bucket
        """
        # Import all buckets in the bucket
        for bid, bucket in buckets.items():
            self.import_bucket(bucket)

    def create_bucket(

        self,
        bucket_id: str,
        event_type: str,
        client: str,
        hostname: str,
        created: Optional[datetime] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Create a bucket.

        If hostname is "!local", the hostname and device_id will be set from the server info.
        This is useful for watchers which are known/assumed to run locally but might not know their hostname (like aw-watcher-web).

        Returns True if successful, otherwise false if a bucket with the given ID already existed.
        """
        # Create a new datetime object.
        if created is None:
            created = datetime.now()
        # Return true if the bucket is in the database.
        if bucket_id in self.db.buckets():
            return False
        # Get the hostname and device id from the server.
        if hostname == "!local":
            info = self.get_info()
            # If data is not set set to null.
            if data is None:
                data = {}
            hostname = info["hostname"]
            data["device_id"] = info["device_id"]
        self.db.create_bucket(
            bucket_id,
            type=event_type,
            client=client,
            hostname=hostname,
            created=created,
            data=data,
        )
        return True

    @check_bucket_exists
    def update_bucket(

        self,
        bucket_id: str,
        event_type: Optional[str] = None,
        client: Optional[str] = None,
        hostname: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
         Update bucket metadata. This is a low - level method that should be used by clients to keep track of changes to buckets.

         @param bucket_id - Id of bucket to update. Must be unique within the bucket.
         @param event_type - Type of event that triggered this update.
         @param client - Client to send this update to. If not specified the default client will be used.
         @param hostname - Hostname associated with this update. If not specified the default hostname will be used.
         @param data - Dict of key / value pairs to send with this update.

         @return ` ` None ` ` to indicate success or failure
        """
        self.db.update_bucket(
            bucket_id,
            type=event_type,
            client=client,
            hostname=hostname,
            data=data,
        )
        return None

    @check_bucket_exists
    def delete_bucket(self, bucket_id: str) -> None:
        """
         Delete a bucket from the storage. This is a no - op if the bucket does not exist

         @param bucket_id - The ID of the bucket to delete

         @return None The response from the S3 server or None if the bucket doesn't
        """
        """Delete a bucket"""
        self.db.delete_bucket(bucket_id)
        logger.debug(f"Deleted bucket '{bucket_id}'")
        return None

    @check_bucket_exists
    def get_event(
        self,
        bucket_id: str,
        event_id: int,
    ) -> Optional[Event]:
        """
         Get an event from a bucket. This is a GET request to the API

         @param bucket_id - The ID of the bucket
         @param event_id - The ID of the event to retrieve

         @return The event or None if not found ( error in json
        """
        logger.debug(
            f"Received get request for event {event_id} in bucket '{bucket_id}'"
        )
        event = self.db[bucket_id].get_by_id(event_id)
        return event.to_json_dict() if event else None

    @check_bucket_exists
    def get_events(
        self,
        bucket_id: str,
        limit: int = -1,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        """Get events from a bucket"""
        logger.debug(f"Received get request for events in bucket '{bucket_id}'")
        # This function is used to set the limit to the next call to the server.
        if limit is None:  # Let limit = None also mean "no limit"
            limit = -1
        events = [
            event.to_json_dict() for event in self.db[bucket_id].get(limit, start, end)
        ]
        return events

    @check_bucket_exists
    def create_events(self, bucket_id: str, events: List[Event]) -> Optional[Event]:
        """
         Create events for a bucket. This is a low - level method for use by clients that don't need to worry about event handling.

         @param bucket_id - The bucket to create the events for
         @param events - A list of events to create

         @return The newly created event or None if one was not
        """
        """Create events for a bucket. Can handle both single events and multiple ones.

        Returns the inserted event when a single event was inserted, otherwise None."""
        return self.db[bucket_id].insert(events)

    @check_bucket_exists
    def get_eventcount(

        self,
        bucket_id: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> int:
        """
         Get eventcount from a bucket. This is a low level method for getting the number of events in a bucket

         @param bucket_id - The id of the bucket
         @param start - The start of the time range to retrieve events from
         @param end - The end of the time range to retrieve events from

         @return The number of events in the time range [ start end
        """
        logger.debug(f"Received get request for eventcount in bucket '{bucket_id}'")
        return self.db[bucket_id].get_eventcount(start, end)

    @check_bucket_exists
    def delete_event(self, bucket_id: str, event_id) -> bool:
        """
         Delete an event from a bucket. This is a destructive operation. You must be sure that there is no event in the bucket before you can delete it

         @param bucket_id - The id of the bucket
         @param event_id - The id of the event

         @return True if the event was deleted False if it was
        """
        """Delete a single event from a bucket"""
        return self.db[bucket_id].delete(event_id)

    @check_bucket_exists
    def heartbeat(self, bucket_id: str, heartbeat: Event, pulsetime: float) -> Event:
        """
         The event to send to the watcher. It must be a : class : ` ~swift. common. events. Event ` object

         @param bucket_id - The bucket to send the heartbeat to
         @param pulsetime - The pulse time in seconds since the epoch.

         @return The newly created or updated event that was sent to the
        """
        """
        Heartbeats are useful when implementing watchers that simply keep
        track of a state, how long it's in that state and when it changes.
        A single heartbeat always has a duration of zero.

        If the heartbeat was identical to the last (apart from timestamp), then the last event has its duration updated.
        If the heartbeat differed, then a new event is created.

        Such as:
         - Active application and window title
           - Example: aw-watcher-window
         - Currently open document/browser tab/playing song
           - Example: wakatime
           - Example: aw-watcher-web
           - Example: aw-watcher-spotify
         - Is the user active/inactive?
           Send an event on some interval indicating if the user is active or not.
           - Example: aw-watcher-afk

        Inspired by: https://wakatime.com/developers#heartbeats
        """
        logger.debug(
            "Received heartbeat in bucket '{}'\n\ttimestamp: {}, duration: {}, pulsetime: {}\n\tdata: {}".format(
                bucket_id,
                heartbeat.timestamp,
                heartbeat.duration,
                pulsetime,
                heartbeat.data,
            )
        )

        # The endtime here is set such that in the event that the heartbeat is older than an
        # existing event we should try to merge it with the last event before the heartbeat instead.
        # FIXME: This (the endtime=heartbeat.timestamp) gets rid of the "heartbeat was older than last event"
        #        warning and also causes a already existing "newer" event to be overwritten in the
        #        replace_last call below. This is problematic.
        # Solution: This could be solved if we were able to replace arbitrary events.
        #           That way we could double check that the event has been applied
        #           and if it hasn't we simply replace it with the updated counterpart.

        last_event = None
        # Get the last event for the bucket
        if bucket_id not in self.last_event:
            last_events = self.db[bucket_id].get(limit=1)
            # Set last_event to the last event
            if len(last_events) > 0:
                last_event = last_events[0]
        else:
            last_event = self.last_event[bucket_id]

        # This function is called by the heartbeat_merge function.
        if last_event:
            # Heartbeat data is the same as heartbeat. data.
            if last_event.data == heartbeat.data:
                merged = heartbeat_merge(last_event, heartbeat, pulsetime)
                # If heartbeat is valid or after pulse window insert new event.
                if merged is not None:
                    # Heartbeat was merged into last_event
                    logger.debug(
                        "Received valid heartbeat, merging. (bucket: {})".format(
                            bucket_id
                        )
                    )
                    self.last_event[bucket_id] = merged
                    self.db[bucket_id].replace_last(merged)
                    return merged
                else:
                    logger.info(
                        "Received heartbeat after pulse window, inserting as new event. (bucket: {})".format(
                            bucket_id
                        )
                    )
            else:
                logger.debug(
                    "Received heartbeat with differing data, inserting as new event. (bucket: {})".format(
                        bucket_id
                    )
                )
        else:
            logger.info(
                "Received heartbeat, but bucket was previously empty, inserting as new event. (bucket: {})".format(
                    bucket_id
                )
            )

        self.db[bucket_id].insert(heartbeat)
        self.last_event[bucket_id] = heartbeat
        return heartbeat

    def query2(self, name, query, timeperiods, cache):
        """
         Queries the database for data. This is the second part of the : meth : ` ~oldman. query ` method.

         @param name - The name of the database to query. This is used to create the query and to access the database in the cache.
         @param query - The query to be executed. This is a list of strings where each string is a field in the database and each field is a value in the form
         @param timeperiods
         @param cache
        """
        result = []
        # Create a query for each timeperiod in the list of timeperiods.
        for timeperiod in timeperiods:
            period = timeperiod.split("/")[
                :2
            ]  # iso8601 timeperiods are separated by a slash
            starttime = iso8601.parse_date(period[0])
            endtime = iso8601.parse_date(period[1])
            query = "".join(query)
            result.append(query2.query(name, query, starttime, endtime, self.db))
        return result

    # TODO: Right now the log format on disk has to be JSON, this is hard to read by humans...
    def get_log(self):
        """Get the server log in json format"""
        payload = []
        with open(get_log_file_path()) as log_file:
            for line in log_file.readlines()[::-1]:
                payload.append(json.loads(line))
        return payload, 200

    def get_dashboard_events(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        events = self.db.get_dashboard_events(starttime=start,endtime=end)

        if len(events) > 0:
            event_start = parser.isoparse(events[0]["timestamp"])
            start_hour = event_start.hour
            start_min = event_start.minute
            start_date_time = event_start

            # Convert events list to JSON object using custom serializer
            events_json = json.dumps({
                "events": events,
                "start_hour": start_hour,
                "start_min": start_min,
                "start_date_time": start_date_time
            }, default=datetime_serializer)

            return json.loads(events_json)
        else: return None

    def get_most_used_apps(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:

        most_used_apps = self.db.get_most_used_apps(starttime=start,endtime=end)

        if len(most_used_apps) > 0:
            events_json = json.dumps({
                "most_used_apps" : most_used_apps
            }, default=datetime_serializer)
            return json.loads(events_json)
        else: return None

    @check_bucket_exists
    def get_formated_events(
        self,
        bucket_id: str,
        limit: int = -1,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        events = self.db.get_dashboard_events(starttime=start,endtime=end)

        current_date = datetime.now().date()
        start_of_day = datetime.combine(current_date, datetime.min.time())
        end_of_day = datetime.combine(current_date, datetime.max.time())
        most_used_apps = self.db.get_most_used_apps(starttime=start_of_day,endtime=end_of_day)

        if len(events) > 0:
            event_start = parser.isoparse(events[0]["timestamp"])
            start_hour = event_start.hour
            start_min = event_start.minute
            start_date_time = event_start

            # Convert events list to JSON object using custom serializer
            events_json = json.dumps({
                "events": events,
                "start_hour": start_hour,
                "start_min": start_min,
                "start_date_time": start_date_time,
                "most_used_apps" : most_used_apps
            }, default=datetime_serializer)

            return json.loads(events_json)
        else: return None

def datetime_serializer(obj):
    """
     Serialize datetime to ISO format. This is used to ensure that dates are converted to ISO format before saving to the database.

     @param obj - The object to serialize. If it is a : class : ` datetime. datetime ` it will be returned as is.

     @return The object serialized as ISO format or ` ` None
    """
    # Return the ISO 8601 format of the object.
    if isinstance(obj, datetime):
        return obj.isoformat()

def event_filter(most_used_apps,data):
    """
        Filter events to include only those that don't have lock apps or login windows

        @param most_used_apps - list of apps that are most used
        @param data - list of events from json file that we want to filter

        @return a list of formatted events for use in event_
    """

    # Convert data to JSON object.
    if (
        isinstance(data, list)
        and len(data) > 0
    ):
        events = sorted(data, key=lambda x: parser.isoparse(x["timestamp"]).timestamp())
        formated_events = []
        start_date_time = None
        start_hour = 24
        start_min = 59

        # This function will add events to the event list
        for e in events:
            # This function is called by the app when the event is triggered.
            if not "LockApp" in e['data']['app'] and not "loginwindow" in e['data']['app']:
                event_start = parser.isoparse(e["timestamp"])
                event_end = event_start + timedelta(seconds=e["duration"])
                # color = getRandomColorVariants()  # Assuming you have this function implemented

                new_event = {
                    **e,
                    "start": event_start.isoformat(),
                    "end": event_end.isoformat(),
                    "event_id": e["id"],
                    "title": e["data"].get("title", ""),
                    # "light": color["light"],
                    # "dark": color["dark"],
                }
                formated_events.append(new_event)

                # Set the start time of the event.
                if start_hour > event_start.hour or (start_hour == event_start.hour and start_min > event_start.minute):
                    start_hour = event_start.hour
                    start_min = event_start.minute
                    start_date_time = event_start

        # Convert events list to JSON object using custom serializer
        events_json = json.dumps({
            "events": formated_events,
            "start_hour": start_hour,
            "start_min": start_min,
            "start_date_time": start_date_time,
            "most_used_apps" : most_used_apps
        }, default=datetime_serializer)

        return json.loads(events_json)  # Parse the JSON string to a Python object

class RalvieServerQueue(threading.Thread):
    def __init__(self, server: ServerAPI) -> None:
        threading.Thread.__init__(self, daemon=True)

        self.server = server
        self.userId = ""
        self.connected = False
        self._stop_event = threading.Event()
        self._attempt_reconnect_interval = 10

    def _try_connect(self) -> bool:
        try:  # Try to connect
            db_key = ""
            cache_key = "sundial"
            cached_credentials = cache_user_credentials(cache_key,"SD_KEYS")
            if cached_credentials != None:
                db_key = cached_credentials.get("encrypted_db_key")
            else:
                db_key == None
            key = load_key("user_key")
            if db_key == None or key == None:
                self.connected = False
                return self.connected
            self.userId = load_key("userId")
            self.connected = True
        except Exception:
            self.connected = False

        return self.connected

    def wait(self, seconds) -> bool:
        return self._stop_event.wait(seconds)

    def should_stop(self) -> bool:
        return self._stop_event.is_set()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while True:
            print("Inside run method")
            self.server.sync_events_to_ralvie()