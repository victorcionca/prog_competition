# C issues to cover

* Detect segmentation fault at runtime
* Infinite loops
* Additional libraries

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
