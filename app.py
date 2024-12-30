from flask import Flask, request, render_template
import re
import spacy
import dns.resolver

app = Flask(__name__)

# Load SpaCy model for text analysis
nlp = spacy.load("en_core_web_sm")

# Function to check for phishing keywords and patterns
def is_phishing_content(email_body):
    phishing_keywords = ["urgent", "verify your account", "click here", "account suspended", "free", "claim now", "password", "security"]
    suspicious_phrases = any(keyword in email_body.lower() for keyword in phishing_keywords)

    # Further check for "too good to be true" types of sentences
    doc = nlp(email_body)
    for ent in doc.ents:
        if ent.label_ == "MONEY":
            suspicious_phrases = True

    return suspicious_phrases

# Function to validate sender's email domain (using DNS)
def check_email_domain_validity(email):
    domain = email.split('@')[-1] if '@' in email else None
    if not domain:
        return False  # Invalid email format

    try:
        # Try resolving the domain's MX records
        dns.resolver.resolve(domain, 'MX')
        return True  # If MX records exist, the domain is valid
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False  # Invalid or non-existent domain
    except Exception as e:
        print(f"Unexpected error while validating domain: {e}")
        return False

# Function to check for suspicious URLs in email body
def check_urls_in_email(email_body):
    urls = re.findall(r'(https?://\S+)', email_body)
    for url in urls:
        # Check if URL is suspicious (you can expand this by integrating with URL scanning APIs like VirusTotal)
        if "bit.ly" in url or "goo.gl" in url:
            return True  # Shortened URLs might be suspicious
    return False

@app.route('/', methods=['GET', 'POST'])
def check_phishing_email():
    if request.method == 'POST':
        # Get sender email and email body from the form
        sender_email = request.form['sender_email']
        email_body = request.form['email_body']

        # Step 1: Validate sender email domain
        valid_sender_domain = check_email_domain_validity(sender_email)

        # Step 2: Check if email content is phishing
        phishing_content = is_phishing_content(email_body)

        # Step 3: Check for suspicious URLs in the email body
        suspicious_urls = check_urls_in_email(email_body)

        # Final phishing check
        is_phishing = phishing_content or not valid_sender_domain or suspicious_urls

        return render_template(
            'result.html',
            result=is_phishing,
            phishing_content=phishing_content,
            valid_sender_domain=valid_sender_domain,
            suspicious_urls=suspicious_urls,
            sender_email=sender_email,
            email_body=email_body
        )

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
