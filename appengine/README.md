# Let's Encrypt for App Engine

This App Engine module automatically keeps the SSL certificates on your App Engine app up-to-date using Let's Encrypt.  Everything is done by your App Engine app - there's no need to touch a commandline, manually upload challenge reponses, or upload certificates to the Cloud Console.

## Getting started

1. **Check out the code.**

       go get github.com/hatstand/gacertsbot/appengine
       cd ${GOPATH:-~/go}/src/github.com/hatstand/gacertsbot/appengine

1. **Deploy the module to your cloud project.**

       gcloud app deploy

    This will create a new module called `ssl-certificates` in your App Engine app.

1. **Update your `dispatch.yaml` to route requests to this module.**  Add the
   following two sections:

       dispatch:
         - url: "*/.well-known/acme-challenge/*"
           service: ssl-certificates    
         - url: "*/ssl-certificates/*"
           service: ssl-certificates

   And then deploy it with:

       gcloud app deploy dispatch.yaml

1. **Enable the Google App Engine API** in your cloud project if it's not enabled
   already.  This allows the module to upload new SSL certificates.

    https://console.developers.google.com/apis/api/appengine.googleapis.com/overview

1. **Visit the status page.**  This will automatically register a new account with
   Let's Encrypt.

        http://YOUR_DOMAIN/ssl-certificates/status

   You'll be prompted to add your App Engine service account as an authorized owner of your domain in Google's Webmaster Tools if it isn't already.

1. *(Optional)* Add an entry to your `cron.yaml` to **automatically renew certificates**
   when they're 30 days away from expiry.  Add the following section:

       cron:
       - description: "Renew SSL certificates"
         url: /ssl-certificates/auto-renew
         schedule: every monday 00:00
         retry_parameters:
           job_retry_limit: 5
           min_backoff_seconds: 60
           max_backoff_seconds: 600

   And then deploy it with:

       gcloud app deploy cron.yaml

## Troubleshooting

If you are still getting 403 errors after enabling the App Engine Admin API, you may also need to [grant the default service account the *App Engine Admin* IAM role](https://console.cloud.google.com/iam-admin/iam/project).
