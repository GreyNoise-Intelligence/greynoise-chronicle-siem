import datetime
import json
import os
import uuid

from greynoise import GreyNoise

# ENVs
GN_API_KEY = os.environ.get("GN_API_KEY")
CUSTOMER_ID = os.environ.get("CHRONICLE_CUSTOMER_ID")
REGION = os.environ.get("REGION")
credentials_file = "sa-info.json"
with open(credentials_file) as f:
    credentials_file = json.load(f)

session = GreyNoise(api_key=GN_API_KEY, integration_name="chronicle-feed-script-v1.0")
NAMESPACE_UUID = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

if not GN_API_KEY:
    print("Missing required Environmental Variable: GN_API_KEY")
    exit(1)
elif not REGION:
    print("Missing required Environmental Variable: REGION")
    exit(1)
elif not CUSTOMER_ID:
    print("Missing required Environmental Variable: CUSTOMER_ID")
    exit(1)


def fetch_greynoise_indicators():
    query = "(classification:malicious OR classification:benign) last_seen:1d"

    print(f"Building indicator list for query: {query}")

    try:
        print("Querying GreyNoise API")
        response = session.query(query=query, exclude_raw=True, size=10000)
    except Exception as e:
        error = f"GreyNoise API connection failure, error {e}"
        return error

    if response["count"] == 0 or len(response["data"]) == 0:
        error = "GreyNoise API query returned no data"
        return error
    else:
        data = response["data"]
        indicator_length = len(data)
        print(f"Processing first page of query results. Total results: {indicator_length}")
        scroll = response["scroll"]
        while scroll:
            print("Querying for next page of results")
            response = session.query(query=query, scroll=scroll, exclude_raw=True, size=10000)
            data.extend(response["data"])
            indicator_length = len(data)
            print(f"Processing next page of results. Total results: {indicator_length}")
            scroll = response["scroll"] if "scroll" in response else False

    return data


def instance_region(region):
    # note, new regions will need to be added here
    regions = {
        "europe": "https://europe-malachiteingestion-pa.googleapis.com",
        "asia": "https://asia-southeast1-malachiteingestion-pa.googleapis.com",
        "us": "https://malachiteingestion-pa.googleapis.com",
    }
    print("Checking for valid Region: " + region)
    if region not in regions:
        raise ValueError("Invalid region")
    print("Region URL: " + str(regions[region]))
    return str(regions[region])


def auth(credentials):
    from google.auth.transport import requests
    from google.oauth2 import service_account

    print("Setting up Auth")

    scopes = ["https://www.googleapis.com/auth/malachite-ingestion"]

    credentials = service_account.Credentials.from_service_account_info(credentials, scopes=scopes)
    return requests.AuthorizedSession(credentials)


def create_entity_v2(entity_json, log_type):
    print("Creating Entities")
    authenticated = auth(credentials_file)

    data = {"customer_id": CUSTOMER_ID, "log_type": log_type, "entities": []}

    data["entities"].append(json.loads(entity_json))

    json_data = json.dumps(data)

    http_endpoint = "{}/v2/entities:batchCreate".format(instance_region(REGION))
    headers = {"content-type": "application/json"}

    r = authenticated.post(url=http_endpoint, data=json_data, headers=headers)

    if r.status_code == 200:
        print("Indicators sent successfully.")
    else:
        print("Indicator submission error:")
        print(r.status_code, r.reason)
    return r


def generate_id_for_ioc_value(ioc_value):
    """Generate a stix 2.1 id for an IOC value."""
    ioc_uuid = str(uuid.uuid5(namespace=NAMESPACE_UUID, name=ioc_value.lower()))
    return f"indicator--{ioc_uuid}"


def send_iocs_to_chronicle(iocs):
    print("Beginning to send Indicators")
    events = []

    for indicator in iocs:
        metadata = {}
        threat = {}
        interval = {}
        entity = {}
        ip_geo_artifact = {"location": {}, "network": {}}

        metadata["vendor_name"] = "GREYNOISE"
        metadata["product_name"] = "GREYNOISE"
        metadata["collected_timestamp"] = str(now())
        metadata["product_entity_id"] = generate_id_for_ioc_value(indicator["ip"])

        interval["start_time"] = str(now())
        interval["end_time"] = str(nowplusseven())

        first_seen_timestamp = format_date_to_timestamp(indicator["first_seen"])
        last_seen_timestamp = format_date_to_timestamp(indicator["last_seen"])

        threat["first_discovered_time"] = first_seen_timestamp
        threat["last_updated_time"] = last_seen_timestamp

        if indicator.get("tags"):
            threat["category_details"] = ", ".join(indicator["tags"])

        if indicator.get("metadata"):
            ip_geo_artifact["location"]["city"] = indicator["metadata"].get("city")
            ip_geo_artifact["location"]["country_or_region"] = indicator["metadata"].get("source_country")
            ip_geo_artifact["network"]["asn"] = indicator["metadata"].get("asn")
            ip_geo_artifact["network"]["organization_name"] = indicator["metadata"].get("organization")

        entity["ip"] = indicator["ip"]
        metadata["entity_type"] = "IP_ADDRESS"
        threat["severity_details"] = "GreyNoise Classification: " + indicator["classification"]
        threat["url_back_to_product"] = "https://viz.greynoise.io/ip/{}".format(indicator["ip"])
        threat["category"] = "NETWORK_RECON"
        threat["summary"] = "Internet Scanning activity observed by GreyNoise"
        entity["ip_geo_artifact"] = ip_geo_artifact

        metadata["threat"] = threat
        metadata["interval"] = interval
        # create the final UDM event
        event = {"metadata": metadata, "entity": entity}
        events.append(event)

    if events:
        counter = 0
        events_len = len(events)
        for i in range(0, events_len, 10000):
            counter = counter + 1
            print("Processing Batch: " + str(counter))
            create_entity_v2(json.dumps(events[i: i + 1000]), "GREYNOISE")
            print("IOCs were returned during this iteration.")
        return "Sending IOCs to Chronicle has been completed."
    else:
        return "No IOCs were returned during the given interval and filter criteria."


def now():
    # Get the current time
    current_time = datetime.datetime.now()

    # Format the current time
    formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    return formatted_time


def nowplusseven():
    # Get the current time
    current_time = datetime.datetime.now()
    future_time = current_time + datetime.timedelta(days=7)

    # Format the current time
    formatted_time = future_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    return formatted_time


def format_date_to_timestamp(date):
    source_date = datetime.datetime.strptime(date, "%Y-%m-%d")
    formatted_time = source_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    return formatted_time


def main():
    start_time = datetime.datetime.now()
    print(f"Start Time: {start_time}")
    try:
        print("Fetching Indicators from GreyNoise")
        indicators = fetch_greynoise_indicators()
    except Exception as e:
        print("Failed to retrieve indicators from GreyNoise: " + str(e))
        return "Failed to retrieve indicators from GreyNoise"

    try:
        print("Sending Indicators to Chronicle")
        submission = send_iocs_to_chronicle(indicators)
        print(submission)
    except Exception as e:
        print("Failed to send indicators to Chronicle: " + str(e))
        return "Failed to send indicators to Chronicle"

    end_time = datetime.datetime.now()
    print(f"End Time: {end_time}")
    duration = end_time - start_time
    print(f"Script Duration: {duration}")
    print("Execution Completed")


main()
