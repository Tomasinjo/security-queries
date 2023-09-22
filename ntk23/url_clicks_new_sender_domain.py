import requests
import whois
import datetime


tenant_id = 'xxxx-xxxxx-xxxx-xxxx'
app_id = 'yyyyy-yyyyyy-yyyyy-yyyyy' 
app_secret = 'zzzzzzzzzzzzzzzzzzzzz'


def get_token():
    url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/token'
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    body = {
        'resource' : 'https://api.security.microsoft.com',
        'client_id' : app_id,
        'client_secret' : app_secret,
        'grant_type' : 'client_credentials'
    }
    resp = requests.post(url, headers=headers, data=body)
    return resp.json().get('access_token')


def domain_age_days(domain):
    w = whois.whois(domain).creation_date
    if isinstance(w, list):
        w = w[0]
    delta = datetime.datetime.now() - w
    return delta.days


def run_adv_hunting(query):
    url = 'https://api.security.microsoft.com/api/advancedhunting/run'
    headers = { 
        'Content-Type' : 'application/json',
        'Accept' : 'application/json',
        'Authorization' : f'Bearer {token}'
    }
    data = {'Query': query}
    resp = requests.post(url, headers=headers, json=data)
    return resp.json().get('Results')


def get_clicked():
    query = '''
        EmailEvents
        | join kind = inner UrlClickEvents on NetworkMessageId
        | where ActionType == "ClickAllowed"
    '''.strip()
    return run_adv_hunting(query)


def main():
    emails_with_clicked_result = get_clicked()
    for email in emails_with_clicked_result:
        sender_domain = email.get('SenderMailFromDomain')
        days_old = domain_age_days(sender_domain)
        if days_old < 30:
            out = f"Sender: {email.get('SenderMailFromAddress')} ({days_old} days old), Recipient: {email.get('RecipientEmailAddress')}, URL clicked: {email.get('Url')}"
            print(out)


if __name__ == "__main__":
    token = get_token()
    main()
