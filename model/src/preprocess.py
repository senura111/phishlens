"""Turn raw emails (.eml / mbox messages or plain text) into the fields the extension can see.

Output fields: sender_name, sender_email, subject, body_text, and links
(each link as {"text": ..., "href": ...}). Raw headers such as SPF/DKIM or Received
are deliberately dropped, because the extension can't read them from Gmail.
"""
