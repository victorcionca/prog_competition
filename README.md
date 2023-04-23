# Setup

* configure static html files in ``static``, modifying to match the subject of the
competition
    * name of the competition in ``index.html``
    * details of score in ``leaderboard.html``
    * details of evaluation in ``submit.html``

* configure in ``competition.go`` the details of the competition
    * names of source files
    * compile command
    * processing of solution output
    * database details

* setup the database; update the schema to fit the solution score

```
> sqlite3 userdb.db
> drop table users;
> .read userdb_schema.sql
```

* the server works with Postmark API to send registration and verification emails
    * ``https://github.com/mattevans/postmark-go``

# Running

``go run competition.go``

The server will be running on port 8080.

# Website structure

* index.html
    * login --> POST to /login
    * register new account --> GET to /registration.html
* registration.html
    * POST to /register
* /register
    * if user doesn't exist store in DB and send verification email --> go back to index
    * if user exists --> show error template that redirects to index
    * if error --> show error template that redirects to index
* ``/verification/user_id``
    * activates the user record in the DB --> show success page, redirect to index
    * on error --> show error template and redirect to index
* dashboard.html: account-based activity; only accessible if user is logged in
    * show the username and best score; links to below
    * submit.html --> form to upload code and submit it
    * /submit     --> POST file
    * /run        --> POST run script to compile and execute code
    * leaderboard.html --> show list of results
