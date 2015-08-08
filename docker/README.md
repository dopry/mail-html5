Dockermail - Email Core
==========
This image provides a self signed certificate authority and minimal mail server based on 'postfix' and 'dovecot'.

All incoming mail to your domains is accepted.
For outgoing mail, only authenticated (logged in with username and password) clients can send messages via STARTTLS.

The default credentials are

admin@example.org : admin
catch-all@example.org : password123

### Setup

You can simply build and run the docker for local development, or you can configure it as an application container.

You will need 2 folders on your host, one to store your configuration and another one to store your email.
In the instructions below we will use the following:
  * `/opt/mail-html5/settings` to store configuration
  * `/opt/mail-html5/vmail` to store the mail


The example config files in 'config/example' are the default configuration for the docker container. You can use them
as a starting point for your own configuration.

1. Add all domains you want to receive mail for to the file `/opt/mail-html5/settings/domains`, like this:

		example.org
		example.net

2. Add user aliases to the file `/opt/mail-html5/settings/aliases`:

		johndoe@example.org       john.doe@example.org
		john.doe@example.org      john.doe@example.org
		admin@forum.example.org   forum-admin@example.org
		@example.net              catch-all@example.net

	An IMAP mail account is created for each entry on the right hand side.
	Every mail sent to one of the addresses in the left column will be delivered to the corresponding account in the right column.

3. Add user passwords to the file `/opt/mail-html5/settings/passwords` like this

		john.doe@example.org:{PLAIN}password123
		admin@example.org:{SHA256-CRYPT}$5$ojXGqoxOAygN91er$VQD/8dDyCYOaLl2yLJlRFXgl.NSrB3seZGXBRMdZAr6

	To get the hash values, you can either install dovecot locally or use `docker exec -it [mail-html5_container_name] bash` to attach to the running container (step 6) and run `doveadm pw -s <scheme-name>` inside, remember to restart your container if you update the settings!

4. Change the hostname in file `/opt/mail-html5/settings/myhostname` to the correct fully qualified domain of your server.

5. Build container

		docker build -t mail-html5 .

6. Run container and map ports 25 and 143 from the host to the container.

	 `docker run -name mail-html5 -d -p 25:25 -p 587:587 -p 143:143 -v /opt/mail-html5/settings:/mail_settings -v /opt/mail-html5/vmail:/vmail mail-html5`

If you're using boot2docker you will need to forward ports 25, 587, and 143 from the docker vm to localhost.