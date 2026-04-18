import os
import json
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='../frontend', template_folder='../frontend')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
MISTRAL_API_KEY = os.environ.get('MISTRAL_API_KEY', '')


def get_claude_response(messages, model='claude-sonnet-4-6'):
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    response = client.messages.create(
        model=model,
        max_tokens=2048,
        messages=messages,
    )
    return response.content[0].text


def get_mistral_response(messages, model='mistral-large-latest'):
    from mistralai import Mistral
    client = Mistral(api_key=MISTRAL_API_KEY)
    response = client.chat.complete(
        model=model,
        messages=messages,
    )
    return response.choices[0].message.content


@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/api/models')
def models():
    available = []
    if ANTHROPIC_API_KEY:
        available += [
            {'id': 'claude-sonnet-4-6', 'name': 'Claude Sonnet 4.6', 'provider': 'anthropic'},
            {'id': 'claude-haiku-4-5-20251001', 'name': 'Claude Haiku 4.5', 'provider': 'anthropic'},
        ]
    if MISTRAL_API_KEY:
        available += [
            {'id': 'mistral-large-latest', 'name': 'Mistral Large', 'provider': 'mistral'},
            {'id': 'mistral-small-latest', 'name': 'Mistral Small', 'provider': 'mistral'},
        ]
    return jsonify(available)


@socketio.on('chat')
def handle_chat(data):
    messages = data.get('messages', [])
    model_id = data.get('model', 'claude-sonnet-4-6')
    provider = data.get('provider', 'anthropic')

    try:
        if provider == 'anthropic':
            if not ANTHROPIC_API_KEY:
                emit('error', {'message': 'Anthropic API-Key nicht konfiguriert'})
                return
            text = get_claude_response(messages, model_id)
        elif provider == 'mistral':
            if not MISTRAL_API_KEY:
                emit('error', {'message': 'Mistral API-Key nicht konfiguriert'})
                return
            text = get_mistral_response(messages, model_id)
        else:
            emit('error', {'message': f'Unbekannter Provider: {provider}'})
            return

        emit('response', {'text': text, 'model': model_id})

    except Exception as e:
        emit('error', {'message': str(e)})


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
