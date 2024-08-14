from flask import current_app
import openai


def generate_chatgpt_response(prompt):
    """
    Memanggil ChatGPT API dengan prompt yang diberikan dan mengembalikan respon.
    :param prompt: Input prompt untuk ChatGPT.
    :return: Respon dari ChatGPT API.
    """
    try:
        models = openai.Model.list()
        print([model.id for model in models["data"]])
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
            temperature=0.7,
        )
        print(response.choices[0].message["content"])
        return response.choices[0].message["content"]
    except Exception as e:
        current_app.logger.error(f"Error calling OpenAI API: {e}")
        return None
