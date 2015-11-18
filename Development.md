# Development



## Pre-requisites

* [Docker](https://www.docker.com/docker-toolbox)  >= 1.9.0
* [Node.JS](https://nodejs.org/en/) >= 4.2.2 LTS
* [Ruby](https://www.ruby-lang.org/en/downloads/) >= 2.2.3
* [SASS](http://sass-lang.com/)

* Grunt

   ```
   npm install -g grunt-cli
   ```

## Git Workflow

1. Fork [seriousmumbo/serious-mail](http://github.com/seriousmumbo/serious-mail)
2. Clone [yourfork/serious-mail] to your local machine.
3. Create a [Feature Branch](https://www.atlassian.com/git/tutorials/comparing-workflows/feature-branch-workflow).
4. Update Code and Commit Changes

   Keep your changes limited to exactly what needs to be updated. Do not make spurious whitespace and formatting changes. Submit whitespace and formatting changes as their own PRs, with no functional changes.

5. Rebase your work on the latest master.

    Any time [seriousmumbo/seriousmail#master](http://github.com/seriousmumbo/seriousmail) is updated, you must rebase all of your feature branches and PRs. It is best to rebase as frequently as possible to minimize and resolve merge conflicts.

6. Submit a pull request to [seriousmumbo/serious-mail](http://github.com/seriousmumbo/serious-mail) with your changes.

## Getting Started
```
cd docker
docker build -t mail-html5 .
docker run --name mail-html5 -d -p 143:143 -p 587:587 mail-html5

cd ..
# build all assets
grunt dist

# start server and watchers that should run during development.
grunt dev
```

For logging in using the mail-html5 client you will need to specify the ip address of the docker
container as the IMAP and SMTP server.





