1. Deploy the code to your cloud project:

    appcfg.py update . -A YOUR_PROJECT

1. Update your dispatch.yaml to route requests to this module.  Add the
   following two sections:

    dispatch:
      - url: "*/.well-known/acme-challenge/*"
        service: ssl-certificates

      - url: "*/ssl-certificates/*"
        service: ssl-certificates

   And then deploy it with:

    appcfg.py update_dispatch .

1. Enable the Google App Engine API in your cloud project if it's not enabled
   already:

    https://console.developers.google.com/apis/api/appengine.googleapis.com/overview

1. Visit the status page.  This will automatically register a new account with
   Let's Encrypt.

    http://YOUR_DOMAIN/ssl-certificates/status
