"""A simple python script to run SSL Scans against a list of sites

Arguments:

Required:

--sites : A comma seperated list of sites to run the scan against

Optional:

--force_test  : Force new tests to be run instead of using existing test results
--use_cache   : Explicitly use cached test results from within the cached time frame
-d, --debug   : Enable debugging output
-v, --verbose : Enable verbose output

Example Usage

python3 ssl_test.py --sites "www.chase.com,www.espn.com,www.google.com"
python3 ssl_test.py --sites "www.google.com" --force_test -v -d

"""
# Built in
import argparse
import datetime

# 3rd party
import requests

from time import sleep

# How old of the cache results we want to use in hours
CACHE_AGE = "1"

# Base API URL
SSL_LABS_BASE_URL = "https://api.ssllabs.com/api/v2"

# The number of times to retry a request before giving up
MAX_RETRIES = 3

# Force a new assessment to be kicked off regardless of if one is available
force_new_test = False

# Turns off using cached results
use_cache = False

# Show debugging output
debug = False
# Show verbose output
verbose = True

# Default fields to get values from each endpoint object
endpoint_fields = [
  "ipAddress", 
  "grade", 
  "hasWarnings", 
  "details.cert.subject", 
  "details.cert.altNames", 
  "details.cert.subject",
  "details.cert.notBefore",
  "details.cert.notAfter"
]
# Use dyanmic endpoint fields
use_end_point_fields = False

# The amount of time in seconds to wait between requests
sleep_time = 15

def enable_force_test() -> None:
  """Turns on debugging output"""
  global force_new_test

  force_new_test = True

def enable_cache_use() -> None:
  """Enables verbose output"""
  global use_cache

  use_cache = True

def enable_debugging() -> None:
  """Turns on debugging output"""
  global debug

  debug = True

def enable_verbose() -> None:
  """Enables verbose output"""
  global verbose

  verbose = True

def increase_sleep_time() -> None:
  """Updates the amount of time we wait between requests to avoid rate limiting"""
  global sleep_time

  sleep_time += 5

def get_nested_dict_value(nested_keys: list[str], dict: dict) -> object:
  """Takes a list of keys and a dictionary and returns the value"""
  if len(nested_keys) == 1:
    return dict[nested_keys[0]]
  else:
    return get_nested_dict_value(nested_keys[1:], dict[nested_keys[0]])

def get_request(request_str: str) -> dict:
  """Wrapper function to initate get request and handle non-200 return codes"""

  retry_num = 0
  while retry_num < MAX_RETRIES:
    try:
      result = requests.get(SSL_LABS_BASE_URL + request_str)
    except requests.exceptions.ConnectionError as e:
      print(f"Unable to connect to remote server with error {e}.")
      print(f"Sleeping {sleep_time} seconds and trying again")
    if result.status_code == 200:
      return result.json()
    
    elif result.status_code == 400:
      print("Malform API call")
      print(result.status_code)
      raise SystemError(f"Error with malformed API call with request string {request_str}")

    elif result.status_code == 429:
      print("We are being rate limited....")
      increase_sleep_time()
      print(f"Increasing sleep time to {sleep_time}....")
      sleep(sleep_time)

    elif result.status_code == 500:
      print("Internal service error....")
      print("Sleeping and running again....")
      sleep(sleep_time)

    elif result.status_code in [503, 529]:
      print("Service overloaded....")
      print("Pausing for 15 minutes....")
      sleep(900)
    
    retry_num += 1
  raise SystemError("Exceeded max retries. Erroring out....")
  
def check_test_exists(site: str, use_cache: bool = False) -> tuple[bool, dict]:
  """Checks to see if the test results are available yet"""
  request_str = f"/analyze?host={site}&all=done"
  
  if use_cache:
    request_str += f"&fromCache=on&maxAge={CACHE_AGE}"

  response = get_request(request_str)

  if response["status"] == "READY":
    exists = True
  else:
    exists = False
  
  return exists, response

def start_new_test(site: str) -> dict:
  """Starts new test on the site that's passed in."""
  request_str = f"/analyze?host={site}&startNew=on&all=done"
  return get_request(request_str)

def get_test_results(site: str) -> dict:
  """Gets test results. Will wait for test to finish if in progress."""
  test_exists, response = check_test_exists(site, use_cache)

  if not test_exists:
    start_new_test(site)

  while not test_exists:
    if verbose:
      print("Test is not ready...")
      print(f"Sleeping {sleep_time} seconds and trying again...")
    sleep(sleep_time)
    test_exists, response = check_test_exists(site)

    if debug:
      print(response)
    
    if response["status"] == "ERROR":
      print(f"Test resulted in an error....")
      print(f"Error Message: {response['statusMessage']}")
      raise SystemError(response["statusMessage"])
  
  return response

def parse_response(response: dict) -> dict:
  """Takes full test result output and pulls relevant fields out. Can be used with either hardcoded fields or dynamic endpoint fields"""

  results = {"host": response["host"], "endpoints": []}
  
  for endpoint in response["endpoints"]:

    if use_end_point_fields:
      ep = {}
      for f in endpoint_fields:
        nested_keys = f.split(".")
        ep[f] = get_nested_dict_value(nested_keys, endpoint)
    else:
      ep = {
        "ip": endpoint["ipAddress"],
        "grade": endpoint["grade"],
        "warnings": endpoint["hasWarnings"],
        "cert_subject": endpoint["details"]["cert"]["subject"],
        "cert_alt_names": endpoint["details"]["cert"]["altNames"],
        "cert_not_before": endpoint["details"]["cert"]["notBefore"],
        "cert_not_after": endpoint["details"]["cert"]["notAfter"]
        }
    
    results["endpoints"].append(ep)
  
  return results

def create_dynamic_endpoint_output(results: dict) -> list[str]:
  """Generates formatted output for dynamic end point fields"""

  output_arr = [
    f"{results['host']}:",
    "  Public Endpoints:"
  ]

  for endpoint in results["endpoints"]:
    print(endpoint.keys())
    for field in endpoint_fields:
      output_arr.append(f"    {field}: {endpoint[field]}")
  
  return output_arr


def create_email_style_output(results: dict) -> list[str]:
  """Creates formatted output and returns it as an array"""
  output_arr = [
    f"{results['host']}:",
    "  Public Endpoints:"
  ]
  for endpoint in results["endpoints"]:
    output_arr.append(f"    IP Address: {endpoint['ip']}")
    output_arr.append(f"    Grade     : {endpoint['grade']}")
    output_arr.append(f"    Warnings  : {str(endpoint['warnings'])}")
    output_arr.append(f"    SSL Cert  :")
    output_arr.append(f"        Subject Name    : {endpoint['cert_subject'].split('=')[1]}")
    output_arr.append(f"        Alternative Name: {' '.join(endpoint['cert_alt_names'])}")
    output_arr.append(f"        Not Valid Before: {datetime.datetime.fromtimestamp(endpoint['cert_not_before']/1000).strftime('%Y-%m-%d')}")
    output_arr.append(f"        Not Valid After : {datetime.datetime.fromtimestamp(endpoint['cert_not_after']/1000).strftime('%Y-%m-%d')}")
  
  return output_arr

def print_results(results: list[dict]) -> None:
  """Outputs the results"""

  for item in results:
    if use_end_point_fields:
      formatted_output = create_dynamic_endpoint_output(item)
    else:
      formatted_output = create_email_style_output(item)
    print("\n".join(formatted_output))

def runner(sites: list[str]) -> None:
  """Runs SSL assesment against list of sites passed in"""

  parsed_results = []
  for site in sites:

    if force_new_test:
      if verbose:
        print("Force new test is enabled....")
        print(f"Starting new test for {site} now....")
      new_test = start_new_test(site)
      if debug:
        print(new_test)
    try:
      response = get_test_results(site)
    except Exception as e:
      print(f"Error getting test results for {site}....")
      print(f"Error was '{e}'")
      continue
    #print(response)
    results = parse_response(response)
    #print(results)
    parsed_results.append(results)
  
  print_results(parsed_results)
  
  

if __name__ == "__main__":
  
  argparse = argparse.ArgumentParser()
  argparse.add_argument("--sites", nargs="?", required=True, help="A comma seperated list of sites to query")
  argparse.add_argument("--force_test", action="store_true")
  argparse.add_argument("--use_cache", action="store_true")
  argparse.add_argument("-d", "--debug", action="store_true")
  argparse.add_argument("-v", "--verbose", action="store_true")
  args = argparse.parse_args()

  if args.force_test:
    print("Enabling force test")
    enable_force_test()
  
  if args.use_cache:
    enable_cache_use()
  
  if args.debug:
    enable_debugging()
  
  if args.verbose:
    enable_verbose()

  sites = args.sites.split(",")
  
  runner(sites)