import smtplib
import random
import string
import easygui
from email.message import EmailMessage

recipient_email = "benjamin.cheng2020@gmail.com"

def generate_pin(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_ver_email(recipient_email,pin):
    sender_email = "securesnap7@gmail.com"
    recipient_email = recipient_email
    subject = 'SecureSnap: Verify your email'
    sender_pw = "rajxmnmbhvfnempj"
    pin = pin
    body = ("PIN: " + str(pin))

    email = EmailMessage()
    email['From'] = sender_email
    email['To'] = recipient_email
    email['Subject'] = subject
    email.set_content(body)

    server = smtplib.SMTP('smtp.gmail.com',587)
    server.starttls()
    server.login(sender_email,sender_pw)

    server.sendmail(sender_email,recipient_email,email.as_string())
    print('mail sent')

def verify_pin(pin_to_verify, pin):
    return pin_to_verify == pin

def main():
    pin = generate_pin()
    send_ver_email(recipient_email,pin)
    while (True):
        pin_to_verify = easygui.passwordbox("Enter verification PIN")
        if verify_pin(pin_to_verify,pin):
            print('correct pin')
            break
        else:
            print('incorrect pin')

main()