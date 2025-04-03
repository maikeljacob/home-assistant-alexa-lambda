"""
Copyright 2019 Jason Hu <awaregit at gmail.com>
Modified in 2025 by Maikel Jacob with assistance from xAI for enhanced Home Assistant and Alexa interactivity.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import json
import logging
import urllib3
from urllib3.exceptions import HTTPError

# Logging setup
_debug = bool(os.environ.get('DEBUG'))
_logger = logging.getLogger('HomeAssistant-SmartHome')
_logger.setLevel(logging.DEBUG if _debug else logging.INFO)

# Environment variables
BASE_URL = os.environ.get('BASE_URL', '').strip("/")
LONG_LIVED_ACCESS_TOKEN = os.environ.get('LONG_LIVED_ACCESS_TOKEN')
VERIFY_SSL = not bool(os.environ.get('NOT_VERIFY_SSL'))

assert BASE_URL, "BASE_URL environment variable is required"

def get_ha_entities(http, token):
    """
    Retrieve visible entities from Home Assistant.
    
    This function queries the Home Assistant /api/states endpoint to fetch all entity states
    and filters out those marked as hidden or disabled, respecting native HA visibility settings.
    
    Args:
        http: urllib3.PoolManager instance for HTTP requests.
        token: Authentication token for Home Assistant API.
    
    Returns:
        List of visible entity dictionaries or None if the request fails.
    """
    try:
        response = http.request(
            'GET',
            f"{BASE_URL}/api/states",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
            },
            timeout=urllib3.Timeout(connect=2.0, read=5.0)
        )
        if response.status == 200:
            entities = json.loads(response.data.decode('utf-8'))
            # Filter out hidden or disabled entities using native HA attributes
            visible_entities = [
                entity for entity in entities
                if not entity.get('attributes', {}).get('hidden', False)
                and 'hidden_by' not in entity.get('attributes', {})
                and 'disabled_by' not in entity.get('attributes', {})
            ]
            return visible_entities
        else:
            _logger.error("Failed to fetch entities: %s", response.data.decode('utf-8'))
            return None
    except Exception as e:
        _logger.error("Error fetching entities: %s", str(e))
        return None

def build_discovery_response(entities, message_id):
    """
    Build an Alexa Discovery response with visible entities.
    
    Constructs a response for Alexa.Discovery.Discover directives, including only visible
    entities with appropriate display categories and capabilities.
    
    Args:
        entities: List of visible entity dictionaries from Home Assistant.
        message_id: Message ID from the Alexa directive header.
    
    Returns:
        Dictionary containing the Alexa Discovery response.
    """
    endpoints = []
    for entity in entities:
        entity_id = entity['entity_id']
        friendly_name = entity['attributes'].get('friendly_name', entity_id)
        domain = entity_id.split('.')[0]
        
        # Assign display categories and interfaces based on entity domain
        if domain == 'switch':
            display_category = 'SWITCH'
            interface = 'Alexa.PowerController'
        elif domain == 'light':
            display_category = 'LIGHT'
            interface = 'Alexa.PowerController'
        else:
            display_category = 'OTHER'
            interface = 'Alexa'

        endpoint = {
            'endpointId': entity_id,
            'friendlyName': friendly_name,
            'description': f"{entity_id} from Home Assistant",
            'manufacturerName': 'Home Assistant',
            'displayCategories': [display_category],
            'capabilities': [
                {
                    'type': 'AlexaInterface',
                    'interface': interface,
                    'version': '3',
                    'properties': {
                        'supported': [{'name': 'powerState'}] if interface == 'Alexa.PowerController' else [],
                        'proactivelyReported': True,  # Enable proactive state updates (requires HA event support)
                        'retrievable': True           # Allow Alexa to query current state
                    }
                }
            ]
        }
        endpoints.append(endpoint)

    return {
        'event': {
            'header': {
                'namespace': 'Alexa.Discovery',
                'name': 'Discover.Response',
                'payloadVersion': '3',
                'messageId': message_id
            },
            'payload': {
                'endpoints': endpoints
            }
        }
    }

def lambda_handler(event, context):
    """
    Handle incoming Alexa directives with enhanced interactivity.
    
    This Lambda function processes Alexa directives, providing custom handling for discovery
    requests by filtering visible entities and forwarding other directives to the Home Assistant
    smart home endpoint.
    
    Args:
        event: The incoming Alexa directive event.
        context: AWS Lambda context object.
    
    Returns:
        A dictionary representing the Alexa response.
    """
    _logger.debug('Event: %s', event)

    directive = event.get('directive')
    if not directive:
        return {'event': {'payload': {'type': 'INVALID_DIRECTIVE', 'message': 'Missing directive'}}}

    header = directive.get('header', {})
    if header.get('payloadVersion') != '3':
        return {'event': {'payload': {'type': 'UNSUPPORTED_OPERATION', 'message': 'Only payloadVersion 3 supported'}}}

    # Extract authentication token from directive
    scope = (directive.get('endpoint', {}).get('scope') or
             directive.get('payload', {}).get('grantee') or
             directive.get('payload', {}).get('scope'))
    if not scope or scope.get('type') != 'BearerToken':
        return {'event': {'payload': {'type': 'INVALID_AUTHORIZATION_CREDENTIAL', 'message': 'Invalid scope'}}}

    token = scope.get('token') or (_debug and LONG_LIVED_ACCESS_TOKEN)
    if not token:
        return {'event': {'payload': {'type': 'INVALID_AUTHORIZATION_CREDENTIAL', 'message': 'No token provided'}}}

    # Initialize HTTP client
    http = urllib3.PoolManager(
        cert_reqs='CERT_REQUIRED' if VERIFY_SSL else 'CERT_NONE',
        timeout=urllib3.Timeout(connect=2.0, read=10.0)
    )

    # Handle Alexa Discovery directive
    if header.get('namespace') == 'Alexa.Discovery' and header.get('name') == 'Discover':
        entities = get_ha_entities(http, token)
        if entities is None:
            return {'event': {'payload': {'type': 'INTERNAL_ERROR', 'message': 'Failed to fetch entities'}}}
        response = build_discovery_response(entities, header.get('messageId'))
        _logger.debug('Discovery response: %s', response)
        return response

    # Forward other directives to Home Assistant smart home endpoint
    try:
        response = http.request(
            'POST',
            f"{BASE_URL}/api/alexa/smart_home",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
            },
            body=json.dumps(event).encode('utf-8'),
        )
        if response.status >= 400:
            error_type = 'INVALID_AUTHORIZATION_CREDENTIAL' if response.status in (401, 403) else 'INTERNAL_ERROR'
            return {'event': {'payload': {'type': error_type, 'message': response.data.decode('utf-8')}}}
        _logger.debug('Response: %s', response.data.decode('utf-8'))
        return json.loads(response.data.decode('utf-8'))
    except HTTPError as e:
        _logger.error("Error communicating with HA: %s", str(e))
        return {'event': {'payload': {'type': 'INTERNAL_ERROR', 'message': 'Communication error'}}}
