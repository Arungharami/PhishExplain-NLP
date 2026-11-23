// Synthetic example messages. All domains use reserved .example / documentation ranges (RFC 2606 / RFC 5737).
export const SAMPLES = Object.freeze([
  { id: "credential", label: "Credential phish (HTML)", tone: "high", text:
`Received: from mail.sender-relay.example (unknown [198.51.100.23]) by mx.recipient.example with ESMTP id 7Q2; Tue, 17 Nov 2026 09:14:02 +0000
Authentication-Results: mx.recipient.example; spf=softfail smtp.mailfrom=bounce@sender-relay.example; dkim=none; dmarc=fail header.from=paypa1-support.example
From: "PayPal Service" <service@paypa1-support.example>
Reply-To: billing.desk@gmail.com
To: you@recipient.example
Subject: Action required: your account has been limited
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Dear customer,</p>
<p>We noticed unusual sign-in activity. Your account has been limited and will be suspended within 24 hours.</p>
<p>To restore access, <a href="http://paypal.com.account-review.example/verify">https://www.paypal.com/myaccount</a> and confirm your password and card details.</p>
<p>PayPal Security Team</p>` },
  { id: "bec", label: "Payment change (BEC)", tone: "high", text:
`From: "Maria Chen (CFO)" <maria.chen.cfo@outlook.com>
To: accounts@company.example
Subject: Urgent wire transfer - confidential

Hi,
I'm in a meeting and can't talk right now. Our supplier has new bank details, so please process a wire transfer of $48,250 today before end of day.
Keep this confidential until the acquisition is announced. Reply to confirm once it is sent.
Maria` },
  { id: "otp", label: "Code request", tone: "high", text:
`From: Account Security <security@acc0unt-help.example>
Subject: Verify it's you

Hello, this is the security team. We are blocking an unauthorized login on your account.
To stop it, reply with the verification code we just sent to your phone. Do it immediately or the account will be locked.
Short link to our help page: https://bit.ly/3xExample` },
  { id: "attachment", label: "Suspicious attachment", tone: "medium", text:
`From: Accounts <invoices@billing-portal.example>
To: you@recipient.example
Subject: Overdue invoice 4471
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="SAMPLEBOUNDARY"

--SAMPLEBOUNDARY
Content-Type: text/plain; charset=utf-8

Please see the attached overdue invoice and remit payment.
--SAMPLEBOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Invoice_4471.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA=
--SAMPLEBOUNDARY
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12
Content-Disposition: attachment; filename="Remittance.xlsm"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAA==
--SAMPLEBOUNDARY--` },
  { id: "benign", label: "Routine message", tone: "low", text:
`From: Research Office <office@university.example>
To: team@university.example
Subject: Weekly meeting notes

Hello team,
The next meeting is Thursday at 2 PM in room 204. The shared notes are at https://docs.university.example/meetings/weekly.
See you then.` },
  { id: "awareness", label: "Security training (hard negative)", tone: "low", text:
`From: Security Training <training@university.example>
Subject: How to recognize suspicious emails

Reminder from security awareness training: we will never ask you to send your password by email, and you should never share a verification code with anyone.
Phishing messages often say "act now" or claim "your account will be suspended". If unsure, contact the help desk using the number on the staff portal.` }
]);
