## Phishing with Calendars
## ICS Templates
- https://github.com/The-Viper-One/OSEP-Notes/blob/main/Phishing/Calendars/ICS_Template.ics

## HTML Templates
- https://github.com/The-Viper-One/OSEP-Notes/blob/main/Phishing/Calendars/HTML_Template_1.html
- https://github.com/The-Viper-One/OSEP-Notes/blob/main/Phishing/Calendars/HTML_Template_2.html
- https://github.com/The-Viper-One/OSEP-Notes/blob/main/Phishing/Calendars/HTML_Microsoft_Teams.html

### SendEmail
Send email to victim with  ICS AND HTML Templates to coerce them into visiting a malicious link.
```
sendEmail -s 192.168.209.121 -t target@security.local -f sender@security.local -u "HR Meeting"  -o message-content-type=html -o message-file=/home/kali/Phishing/Microsoft_Teams_Template.html -a /home/kali/Phishing/Invite.ics -v
```
![image](https://github.com/user-attachments/assets/a2b40872-cd51-44b6-a9ee-0c6a0072aabe)



## Credential Stealing with Responder
Credentials can also be captured with Responder when the target is coerced into authenticating to an attacer controller server.

![image](https://github.com/user-attachments/assets/a723ad9d-ab37-42da-b75b-263cf9c3ab9c)


![image](https://github.com/user-attachments/assets/3e098ab1-5153-4dcf-b89a-9e40fe7690ee)
