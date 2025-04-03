# Home Assistant Alexa Lambda

Enhanced Alexa Smart Home Lambda function for Home Assistant.

## Overview
This is a modified version of Jason Hu's original 2019 Alexa Smart Home Lambda function, enhanced in 2025 by Maikel Jacob with assistance from xAI. The improvements focus on better integration between Home Assistant (HA) and Alexa, leveraging HA's native visibility controls and enabling more interactive device updates.

## Features
1. **Native HA Visibility Support**:
   - Filters entities based on HA's `hidden`, `hidden_by`, and `disabled_by` attributes, ensuring only visible entities are exposed to Alexa.
2. **Custom Discovery Handling**:
   - Processes `Alexa.Discovery.Discover` directives directly, building a response with visible entities.
3. **Enhanced Interactivity**:
   - Adds `proactivelyReported` and `retrievable` capabilities for proactive updates and real-time state queries.
4. **Improved Error Handling**:
   - Standardized Alexa error responses for invalid directives, authentication, and communication errors.

## Requirements
- **AWS Lambda Environment Variables**:
  - `BASE_URL`: Your Home Assistant URL (e.g., `https://your-ha.duckdns.org`).
  - `LONG_LIVED_ACCESS_TOKEN`: A long-lived access token from HA (generate in **Settings > Profile > Long-Lived Access Tokens**).
  - `NOT_VERIFY_SSL`: Set to `true` if using an unverified SSL certificate (optional).
  - `DEBUG`: Set to `true` for detailed logging (optional).
- **Home Assistant**:
  - Ensure HA is accessible via the provided `BASE_URL`.
  - For proactive updates, configure HA with Nabu Casa or a custom WebSocket solution.

## Installation
1. Deploy this code to an AWS Lambda function.
2. Configure the environment variables in the Lambda console.
3. Link the Lambda function to your Alexa Skill (Smart Home skill type).
4. In Home Assistant, ensure desired entities are visible (not disabled or hidden).

## Usage
- Trigger discovery with "Alexa, discover devices" to load visible HA entities.
- Control devices with commands like "Alexa, turn on [friendly_name]".
- Disable unwanted entities in HA (**Settings > Devices & Services > Entities**) to exclude them from Alexa.

## Improvements Over Original
- **Original (Jason Hu, 2019)**: Simple proxy forwarding all directives to HA's `/api/alexa/smart_home`.
- **Modified (Maikel Jacob, 2025)**:
  - Custom discovery with visibility filtering.
  - Support for proactive updates and state retrieval.
  - Better error handling and logging.

## Limitations
- Proactive updates require HA to send events (e.g., via Nabu Casa).
- Only basic `Alexa.PowerController` capabilities are implemented; additional interfaces (e.g., for sensors) need expansion.
- Large entity lists may slow down `/api/states` calls; consider caching for scalability.

## Contributing
Feel free to fork this repository, submit issues, or propose enhancements via pull requests.

## Credits
- **Original Author**: Jason Hu (2019)
- **Modified By**: Maikel Jacob (2025)
- **Assisted By**: xAI (2025)
