import openai


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
