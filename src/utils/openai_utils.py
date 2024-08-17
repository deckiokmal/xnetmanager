import openai


template_function_description = [
    {
        "name": "generate_device_configuration_template",
        "description": "Generate a Jinja2 template with YAML parameters for configuring network devices like Fortinet. The response should only contain the template with no extra text to avoid errors when pushing the configuration to the devices.",
        "parameters": {
            "type": "object",
            "properties": {
                "device_type": {
                    "type": "string",
                    "description": "Type of network device (e.g., Fortinet).",
                },
                "hostname": {
                    "type": "string",
                    "description": "Hostname of the network device.",
                },
                "interfaces": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Interface name.",
                            },
                            "ip_address": {
                                "type": "string",
                                "description": "IP address of the interface.",
                            },
                            "subnet_mask": {
                                "type": "string",
                                "description": "Subnet mask of the interface.",
                            },
                        },
                        "required": ["name", "ip_address", "subnet_mask"],
                    },
                    "description": "List of interfaces to configure.",
                },
                "routes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "destination": {
                                "type": "string",
                                "description": "Destination network.",
                            },
                            "gateway": {
                                "type": "string",
                                "description": "Gateway IP address for the route.",
                            },
                        },
                        "required": ["destination", "gateway"],
                    },
                    "description": "List of static routes.",
                },
            },
            "required": ["device_type", "hostname", "interfaces"],
        },
    }
]


def validate_generated_template_with_openai(config, vendor):
    response = openai.ChatCompletion.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": f"You are an expert in network device configuration and syntax validation for {vendor} devices.",
            },
            {
                "role": "user",
                "content": f"Please validate the following {vendor} network device configuration:\n\n{config}",
            },
        ],
    )

    # Extract the validation result from the response
    validation_result = response["choices"][0]["message"]["content"]
    print(validation_result)

    if "valid" in validation_result.lower():
        return {"is_valid": True}
    else:
        return {"is_valid": False, "error_message": validation_result}
