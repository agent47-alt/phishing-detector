import os
import re
import json
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_FILE = 'credentials.json'


def get_flow():
    flow = InstalledAppFlow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=SCOPES,
    )
    flow.redirect_uri = 'http://127.0.0.1:8000/email-scan/callback/'
    return flow


def get_gmail_service(token_json):
    creds = Credentials.from_authorized_user_info(json.loads(token_json), SCOPES)
    service = build('gmail', 'v1', credentials=creds)
    return service


def extract_urls(text):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)


def get_email_body(message):
    body = ''
    try:
        payload = message['payload']

        if 'body' in payload and payload['body'].get('data'):
            data = payload['body']['data']
            body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')

        if 'parts' in payload:
            for part in payload['parts']:
                if 'parts' in part:
                    for subpart in part['parts']:
                        data = subpart['body'].get('data', '')
                        if data:
                            body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                else:
                    data = part['body'].get('data', '')
                    if data:
                        body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    except:
        pass
    return body


def scan_emails(token_json, max_emails=50):
    service = get_gmail_service(token_json)
    results = []

    messages = service.users().messages().list(
        userId='me',
        maxResults=max_emails
    ).execute()

    if 'messages' not in messages:
        return []

    for msg in messages['messages']:
        try:
            message = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='full'
            ).execute()

            headers = message['payload']['headers']
            subject = next(
                (h['value'] for h in headers if h['name'] == 'Subject'),
                'No Subject'
            )
            sender = next(
                (h['value'] for h in headers if h['name'] == 'From'),
                'Unknown'
            )

            body = get_email_body(message)
            urls = extract_urls(body)

            results.append({
                'subject': subject,
                'sender': sender,
                'urls': urls,
                'url_count': len(urls)
            })
        except:
            pass

    return results