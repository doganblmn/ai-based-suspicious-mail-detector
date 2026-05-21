# AI-Based Suspicious Mail Detector

AI-Based Suspicious Mail Detector is a frontend-only cybersecurity demo project.  
It helps users analyze suspicious emails by checking sender identity, email content, suspicious phrases, and unsafe links.

## Live Demo

GitHub Pages link will be added here.

## Project Purpose

The purpose of this project is to help users understand whether an email may be suspicious before clicking links or sharing personal information.

The application analyzes:

- Sender name
- Sender email address
- Email body

Then, it generates:

- Risk level
- Risk score
- Sender analysis
- Content analysis
- Suspicious phrases
- Suspicious links
- Security feedback

## Technologies Used

- HTML
- CSS
- JavaScript

## How to Run

You can run the project by opening the `index.html` file in a browser.

No installation, backend server, database, or API key is required.

## Demo Note

This demo does not use a real AI API.  
It uses a local AI-like analysis engine for presentation purposes.

In a real-world version, this engine can be replaced with a trained AI model or an LLM API.

## Test Emails

The project can be tested with Safe, Medium Risk, and High Risk email examples.

### Safe Email Example

Sender Name: Project Team  
Sender Email: team@university.edu  

Email Body:

Hello,

This is a reminder for our project meeting tomorrow at 10:00 AM.  
We will discuss the current progress, completed tasks, and the next steps for the project.

Best regards,  
Project Team

### Medium Risk Email Example

Sender Name: Billing Support  
Sender Email: billing.support@gmail.com  

Email Body:

Dear customer,

We noticed an issue with your recent invoice.  
Please review your payment information today to avoid delays.

Regards,  
Support Team

### High Risk Email Example

Sender Name: PayPal Support  
Sender Email: paypal.security@gmail.com  

Email Body:

Dear customer,

Your account will be suspended today.  
Please verify your account immediately.

Click this link and enter your password:  
http://bit.ly/secure-paypal-login

Failure to act now may block your account permanently.

## Technical Report

The technical report is available in the `docs` folder.

[Technical Report](docs/Technical_Report.pdf)