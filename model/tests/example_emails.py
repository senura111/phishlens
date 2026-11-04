"""Five hand-written emails in a modern style, shaped like POST /analyze requests.

They're deliberately unlike the 2002 mailing-list ham the model was trained on, to
see how it does on the kind of email a real inbox gets. Shops and people are made up;
the password reset uses Dropbox's real domains to check the brand rules leave a
genuine sender alone.
"""

PHISHING_LOOKALIKE = {
    "sender_name": "PayPal Service",
    "sender_email": "service@paypal-account-review.com",
    "subject": "Action required: your account has been limited",
    "body_text": (
        "Dear Customer,\n\n"
        "We noticed unusual sign-in activity on your PayPal account. As a precaution, "
        "we have limited what you can do with your account until you confirm your "
        "identity.\n\n"
        "Please confirm your account details within 24 hours to avoid permanent "
        "suspension.\n\n"
        "Confirm now: https://www.paypal.com/signin\n\n"
        "Thank you for helping us keep your account safe.\n"
        "PayPal Security Team"
    ),
    "links": [
        {
            "text": "https://www.paypal.com/signin",
            "href": "http://paypal-account-review.com/secure/login.php?id=88213",
        }
    ],
}

PERSONAL = {
    "sender_name": "Maya Perera",
    "sender_email": "maya.perera@gmail.com",
    "subject": "Saturday hike?",
    "body_text": (
        "Hey!\n\n"
        "Are you still up for the Ella hike on Saturday? Nimal and Priya are in too. "
        "I was thinking we take the early train from Kandy and grab breakfast at that "
        "place near the station.\n\n"
        "Let me know by Thursday so I can book the tickets. I'll bring snacks, you "
        "bring the good camera :)\n\n"
        "Maya"
    ),
    "links": [],
}

NEWSLETTER = {
    "sender_name": "Northwind Outfitters",
    "sender_email": "hello@email.northwindoutfitters.com",
    "subject": "Our autumn collection is here: 20% off this weekend",
    "body_text": (
        "View in browser\n\n"
        "Hi Alex,\n\n"
        "Cooler days are coming, and our new autumn collection is ready for them. "
        "Waxed jackets, merino layers and the trail boots you asked us to bring back.\n\n"
        "This weekend only, get 20% off everything with code AUTUMN20. Free shipping "
        "on orders over $50.\n\n"
        "Shop the collection\n\n"
        "Offer ends Sunday at midnight.\n\n"
        "You're receiving this email because you signed up at northwindoutfitters.com.\n"
        "Unsubscribe | Manage preferences\n"
        "Northwind Outfitters, 120 Harbor Street, Portland, OR 97201\n"
        "© 2026 Northwind Outfitters. All rights reserved."
    ),
    "links": [
        {
            "text": "View in browser",
            "href": "https://email.northwindoutfitters.com/view/8c1f2a",
        },
        {
            "text": "Shop the collection",
            "href": "https://u4821.ct.sendgrid.net/ls/click?upn=ab12cd34",
        },
        {
            "text": "northwindoutfitters.com",
            "href": "https://u4821.ct.sendgrid.net/ls/click?upn=ef56gh78",
        },
        {
            "text": "Unsubscribe",
            "href": "https://email.northwindoutfitters.com/unsubscribe?u=4821",
        },
        {
            "text": "Manage preferences",
            "href": "https://email.northwindoutfitters.com/preferences?u=4821",
        },
    ],
}

PASSWORD_RESET = {
    "sender_name": "Dropbox",
    "sender_email": "no-reply@dropbox.com",
    "subject": "Reset your Dropbox password",
    "body_text": (
        "Hi Alex,\n\n"
        "Someone (hopefully you) asked us to reset the password for your Dropbox "
        "account. Click the button below to choose a new one.\n\n"
        "Reset password\n\n"
        "This link expires in 24 hours. If you didn't ask to reset your password, you "
        "can ignore this email and your password won't change.\n\n"
        "Thanks,\n"
        "The Dropbox team"
    ),
    "links": [
        {
            "text": "Reset password",
            "href": "https://www.dropbox.com/password_reset?token=Zk3pQ9",
        },
        {"text": "Help Center", "href": "https://help.dropbox.com/"},
    ],
}

RECEIPT_WITH_PDF = {
    "sender_name": "Kandy Books",
    "sender_email": "orders@kandybooks.lk",
    "subject": "Your receipt for order KB-20931",
    "body_text": (
        "Thanks for your order, Alex!\n\n"
        "Order KB-20931\n"
        "The Overstory, Richard Powers  x1  LKR 4,200.00\n"
        "Sapiens, Yuval Noah Harari  x1  LKR 3,250.00\n"
        "Total paid: LKR 7,450.00\n"
        "Payment method: Visa ending in 4242\n\n"
        "Your invoice is attached as a PDF. Your books will ship within 2 business "
        "days, and we'll email you a tracking link.\n\n"
        "View your order\n\n"
        "Kandy Books, 14 Dalada Veediya, Kandy"
    ),
    "links": [
        {
            "text": "View your order",
            "href": "https://kandybooks.lk/account/orders/KB-20931",
        }
    ],
    "attachments": ["Invoice_KB-20931.pdf"],
}

EXAMPLES = {
    "phishing (lookalike + mismatched link)": (PHISHING_LOOKALIKE, "phishing"),
    "personal email between friends": (PERSONAL, "safe"),
    "marketing newsletter": (NEWSLETTER, "safe"),
    "password reset": (PASSWORD_RESET, "safe"),
    "receipt with PDF invoice": (RECEIPT_WITH_PDF, "safe"),
}
