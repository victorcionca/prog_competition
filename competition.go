package main

import (
    "fmt"
    "log"
    "io"
    "os"
    "os/exec"
    "bytes"
    "strings"
    "strconv"
    "errors"
    "sort"
    "math/rand"
    "mime/multipart"
    "encoding/base64"
    text_template "text/template"
    "html/template"
    "net/http"
    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
    "github.com/sendgrid/sendgrid-go"
    "github.com/sendgrid/sendgrid-go/helpers/mail"
)

const (
    userDbFile = "userdb.db"
    leaderboardTemplate = "static/leaderboard.html"
    webaddress = "http://localhost:8080"
    emailTemplate = `Dear {{ .Name }},
        Thank you for registering for the C Programming competition.
        To activate your account follow the link below:
        {{ .Link }}`
    user_folders = "user_folders"
)

var userDb *sql.DB
var session_store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

type UserRecord struct {
    Email string
    Salt []byte
    Password string
    Name string
    Id string
    Score int
    Verified int
}

type LeaderBoardData struct {
    Title string
    Users []UserRecord
}

func GetUserFolder(userid string) string {
    return user_folders+"/user_"+userid[:20]
}

func GetUserSolutionFile(userid string) string {
    return GetUserFolder(userid)+"/gradient_sol.c"
}

func PrepareUserFolder(userid string) error {
    userfolder := GetUserFolder(userid)
    // Create the folder
    var err error
    if err = os.Mkdir(userfolder, os.ModePerm); err != nil {
        return err
    }
    // Copy in the folder the template files
    cmd := exec.Command("cp", user_folders+"/gradient.c", userfolder+"/")
    if err = cmd.Run(); err != nil {
        return err
    }
    cmd = exec.Command("cp", user_folders+"/gradient.h", userfolder+"/")
    if err = cmd.Run(); err != nil {
        return err
    }

    return nil
}

func UploadFile(file multipart.File, userid string) error {
    // Create user file
    dst, err := os.Create(GetUserSolutionFile(userid))
    defer dst.Close()
    if err != nil {
        return err
    }

    // Copy the uploaded file to the created file on the filesystem
    if _, err := io.Copy(dst, file); err != nil {
        return err
    }

    return nil
}

func TryCompile(userid string) (string, error) {
    // Change directory into the users folder
    var err error
    var out []byte
    wdir, _ := os.Getwd()
    err = os.Chdir(GetUserFolder(userid))
    if err != nil {
        return "", err
    }

    //  Run gcc, capturing the output
    defer os.Chdir(wdir)
    out, err = exec.Command("gcc", "gradient.c", "gradient_sol.c", "-lm", "-ogradient").CombinedOutput()
    if err != nil {
        return string(out), err
    }

    return string(out), nil
}

// Runs a solution and returns a run message (e.g. SEGFAULT), obtained score
func RunSolution(userid string) (string, int) {
    // Change directory into the users folder
    var err error
    var out []byte
    score := -1
    wdir, _ := os.Getwd()
    _ = os.Chdir(GetUserFolder(userid))
    defer os.Chdir(wdir)

    // Check that binary exists
    tmpwdir, _ := os.Getwd()
    if _, err := os.Stat(tmpwdir + "/gradient"); errors.Is(err, os.ErrNotExist) {
        return "Solution hasn't been compiled yet!", score
    }

    //  Run solution, capturing the output
    out, err = exec.Command("./gradient").CombinedOutput()
    log.Println("Result: "+string(out))
    if err == nil {
        score, _ = strconv.Atoi(strings.TrimSpace(string(out)))
        log.Printf("No error")
    }else{
        // Must extract the error code
        exitCode := err.(*exec.ExitError).ExitCode()
        log.Printf("%v", exitCode)
    }

    return string(out), score
}

// Hashes the string
// A salt of saltlength can be added to the hash.
// If saltlength == 0 the salt is read from the salt parameter.
// If saltlength > 0 the salt is generated and returned.
func HashString(_string string, saltlength int, salt []byte) (string, []byte, error) {
    data := []byte(_string)
    var randbytes []byte
    if saltlength > 0 {
        randbytes = make([]byte, saltlength)
        rand.Read(randbytes)
    }else{
        randbytes = salt
    }
    copy(data[len(data):], randbytes)
    bytes, err := bcrypt.GenerateFromPassword(data, 10)
    return base64.StdEncoding.EncodeToString(bytes), randbytes, err
}

func HashPassword(password string, saltlength int) (string, []byte, error) {
    data := make([]byte, len(password)+saltlength)
    copy(data, []byte(password))
    rand.Read(data[len(password):])
    bytes, err := bcrypt.GenerateFromPassword(data, 10)
    return string(bytes), data[len(password):], err
}

// Compares the user's password with the hashed value.
// Returns true on match, false otherwise
func VerifyPassword(password string, salt []byte, hashed string) bool {
    password_bytes := make([]byte, len(password)+len(salt))
    copy(password_bytes, []byte(password))
    copy(password_bytes[len(password):], salt)
    err := bcrypt.CompareHashAndPassword([]byte(hashed), password_bytes)
    return err == nil
}

// Send a verification email to the user
func SendVerificationMail(user UserRecord) error {
    from := mail.NewEmail("SOFT7019", "victor.cionca@mtu.ie")
    to := mail.NewEmail(user.Name, user.Email)
    subject := "SOFT7019 A1 Competition: verify account"
    // Generate email text
    t := text_template.Must(text_template.New("email").Parse(emailTemplate))
    buf := &bytes.Buffer{}
    data := map[string]interface{}{
        "Name": user.Name,
        "Link": webaddress+"/verification/"+user.Id,
    }
    if err := t.Execute(buf, data); err != nil {
        return err
    }
    plainTextContent := buf.String()
    message := mail.NewSingleEmail(from, subject, to, plainTextContent, "")
    client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
    _, err := client.Send(message)
    if err != nil {
        return err
    }
    log.Println("Sent verification email to ", user.Name)
    return nil
}

/* --------------------------------------------------------------------------- */
// Database functions

func AddUser(user UserRecord) error {
    addUserSQL := "INSERT INTO users(email, salt, password, name, id, score, verified) VALUES (?, ?, ?, ?, ?, ?, 0)"
    statement, err := userDb.Prepare(addUserSQL)
    if err != nil {
        return err
    }
    _, err = statement.Exec(user.Email, user.Salt, user.Password, user.Name, user.Id, -1)
    return err
}

func ValidateUser(id string) error {
    validateUserSQL := "UPDATE users SET verified = 1 WHERE id = ?";
    statement, err := userDb.Prepare(validateUserSQL)
    if err != nil {
        return err
    }
    _, err = statement.Exec(id)
    return err
}

func UpdateScore(userid string, score int) error {
    updateScoreSQL := "UPDATE users SET score = ? WHERE id = ?";
    statement, err := userDb.Prepare(updateScoreSQL)
    if err != nil {
        return err
    }
    _, err = statement.Exec(score, userid)
    return err
}

// Checks that the email and username don't already exist in the database
// Returns false if the details don't exist, or true otherwise
func HaveUserCollision(user UserRecord) (bool, error) {
    getUserSQL := "SELECT COUNT(*) FROM users where email == ? OR name == ?"
    statement, err := userDb.Prepare(getUserSQL)
    if err != nil {
        return false, err
    }
    var num_results int
    err = statement.QueryRow(user.Email, user.Name).Scan(&num_results)
    if err != nil {
        return false, err
    }
    return num_results != 0, nil
}

// Retrieves from the database the user record with given email, or nil if the
// user doesn't exist.
func GetUser(email string) (UserRecord, error) {
    var user UserRecord
    user.Email = ""
    getUserSQL := "SELECT * FROM users where email == ?"
    statement, err := userDb.Prepare(getUserSQL)
    if err != nil {
        return user, nil
    }
    row := statement.QueryRow(email)
    err = row.Scan(&user.Email, &user.Salt, &user.Password, &user.Name, &user.Id, &user.Score, &user.Verified)
    if err != nil {
        return user, err
    }else{
        return user, nil
    }
}

// Get all the user records from the DB
func GetUserRecords(onlyValid bool) ([]UserRecord, error) {
    rows, err := userDb.Query("SELECT * FROM users")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var records []UserRecord
    for rows.Next() {
        var record UserRecord
        err := rows.Scan(&record.Email, &record.Salt, &record.Password, &record.Name, &record.Id, &record.Score, &record.Verified)
        if err != nil {
            return nil, err
        }
        if onlyValid && record.Verified == 1 && record.Score > 0 {
            records = append(records, record)
        }
    }
    return records, nil
}
/* --------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------- */
// HTTP handlers
func HandleLeaderboard(w http.ResponseWriter, r *http.Request) {
    session, _ := session_store.Get(r, "cprogramming")
    //errTemplate := template.Must(template.ParseFiles("error_template.html"))
    // Parse leaderboard template
    leadertmpl := template.Must(template.ParseFiles(leaderboardTemplate))

    // Check if the user is authenticated
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Read the user records from the DB
    userRecords, err := GetUserRecords(true)
    if err != nil {
        http.ServeFile(w, r, "static/index.html")
    }
    // Sort the userRecords in increasing order of score
    sort.SliceStable(userRecords, func(i,j int) bool {
        return userRecords[i].Score < userRecords[j].Score
    })

    data := LeaderBoardData{
        Title: "Hello",
        Users: userRecords,
    }
    leadertmpl.Execute(w, data)
}

func HandleLogout(w http.ResponseWriter, r *http.Request){
    session, _ := session_store.Get(r, "cprogramming")
    errTemplate := template.Must(template.ParseFiles("error_template.html"))

    session.Values["authenticated"] = false
    session.Values["username"] = ""
    session.Values["email"] = ""

    err := session.Save(r, w)
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error creating session. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    http.ServeFile(w, r, "static/index.html")
}

func HandleLogin(w http.ResponseWriter, r *http.Request){
    session, _ := session_store.Get(r, "cprogramming")
    errTemplate := template.Must(template.ParseFiles("error_template.html"))

    // Check that we have the email and password
    user_email := r.FormValue("email")
    user_password := r.FormValue("password")

    // Search for the user in the database based on the email
    userRecord, err := GetUser(user_email)
    if err != nil{
        data := map[string]interface{}{
            "Message": "Error searching for user in DB. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    if userRecord.Email == ""{
        data := map[string]interface{}{
            "Message": "User does not exist.",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Hash the user's password and compare with the database value
    if VerifyPassword(user_password, userRecord.Salt, userRecord.Password) == false {
        data := map[string]interface{}{
            "Message": "Password incorrect.",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    if userRecord.Verified == 0 {
        data := map[string]interface{}{
            "Message": "User email has not been validated.",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Create a session for the user
    session.Values["authenticated"] = true
    session.Values["userid"] = userRecord.Id
    session.Values["username"] = userRecord.Name
    session.Values["email"] = userRecord.Email
    session.Values["score"] = userRecord.Score
    err = session.Save(r, w)
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error creating session. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    HandleDashboard(w, r)
}

func HandleVerification(w http.ResponseWriter, r *http.Request){
    // Prepare the error template
    errTemplate := template.Must(template.ParseFiles("error_template.html"))

    // Extract the user_id from the request
    vars := mux.Vars(r)
    if vars["user_id"] == "" {
        log.Println("Validation request did not contain user id")
        http.ServeFile(w, r, "/index.html")
        return
    }

    // TODO: search for user first

    err := ValidateUser(vars["user_id"])
    if err != nil {
        log.Println("Could not validate the user")
        data := map[string]interface{}{
            "Message": "Incorrect validation link. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Create a folder for the user
    err = PrepareUserFolder(vars["user_id"])
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error preparing user folders. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    data := map[string]interface{}{
        "Message": "User is activated. You can now login through main page.",
            "Link": "/",
    }
    errTemplate.Execute(w, data)
    return
}

func HandleRegistration(w http.ResponseWriter, r *http.Request){
    // Prepare the error template
    errTemplate := template.Must(template.ParseFiles("error_template.html"))

    // Validate the user's email
    userEmail := r.FormValue("email")
    if userEmail == "" {
        data := map[string]interface{}{
            "Message": "Empty user email",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Validate the user's password
    userPassword := r.FormValue("password")
    if userPassword == "" {
        data := map[string]interface{}{
            "Message": "Empty user password",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Validate the user's name
    userName := r.FormValue("name")
    if userName == "" {
        data := map[string]interface{}{
            "Message": "Empty user name",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Generate an id
    userId, _, err := HashString(userEmail+userName, 16, nil)
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error generating user id. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    log.Println("User details: ", userEmail, userPassword, userName, userId)

    var user UserRecord
    user.Email = userEmail
    user.Password, user.Salt, _ = HashPassword(userPassword, 16)
    user.Name = userName
    user.Id = userId
    user.Score = -1

    // Check that the username or email don't exist in the DB
    var collision bool
    collision, err = HaveUserCollision(user)
    if err != nil {
        data := map[string]interface{}{
            "Message": "Database error, checking collisions. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }
    if collision {
        data := map[string]interface{}{
            "Message": "Username or email already registered.",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Generate and send the email
    if err = SendVerificationMail(user); err != nil {
        data := map[string]interface{}{
            "Message": "Error sending verification email. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Store the user's account as unverified in the database
    err = AddUser(user)
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error adding user to DB. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    data := map[string]interface{}{
        "Message": "Verification email sent to your email.",
            "Link": "/",
    }
    errTemplate.Execute(w, data)
    return
}

func HandleDashboard(w http.ResponseWriter, r *http.Request) {
    session, _ := session_store.Get(r, "cprogramming")
    dashtemplate := template.Must(template.ParseFiles("static/dashboard.html"))

    // Check if the user is authenticated
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    data := map[string]interface{}{
        "Username": session.Values["username"],
        "Score": session.Values["score"],
    }
    dashtemplate.Execute(w, data)
    return
}

func HandleSubmit(w http.ResponseWriter, r *http.Request) {
    session, _ := session_store.Get(r, "cprogramming")
    subtemplate := template.Must(template.ParseFiles("static/submit.html"))

    // Check if the user is authenticated
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    data := map[string]interface{}{
        "Username": session.Values["username"],
        "Score": session.Values["score"],
    }
    subtemplate.Execute(w, data)
    return
}

func HandleUpload(w http.ResponseWriter, r *http.Request) {
    session, _ := session_store.Get(r, "cprogramming")
    // Prepare the error template
    errTemplate := template.Must(template.ParseFiles("error_template.html"))

    // Check if the user is authenticated
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Restrict upload to ~65KB files
    r.ParseMultipartForm(1 << 16)

    // Get handler for filename, size and headers
    file, _, err := r.FormFile("solution")
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error uploading solution file. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/static/submit.html",
        }
        errTemplate.Execute(w, data)
        return
    }
    defer file.Close()

    err = UploadFile(file, session.Values["userid"].(string))
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error uploading solution file. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/static/submit.html",
        }
        errTemplate.Execute(w, data)
        return
    }

    data := map[string]interface{}{
        "Message": "File uploaded successfully. You will have to compile before running.",
            "Link": "/static/submit.html",
    }
    errTemplate.Execute(w, data)
    return
}

func HandleCompile(w http.ResponseWriter, r *http.Request) {
    session, _ := session_store.Get(r, "cprogramming")
    // Prepare the error template
    outTemplate := template.Must(template.ParseFiles("output_template.html"))

    // Check if the user is authenticated
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    compile_result, _ := TryCompile(session.Values["userid"].(string))
    if len(strings.TrimSpace(compile_result)) == 0{
        compile_result = "Success!"
    }
    data := map[string]interface{}{
        "Message": compile_result,
    }

    outTemplate.Execute(w, data)
    return
}

func HandleRun(w http.ResponseWriter, r *http.Request) {
    session, _ := session_store.Get(r, "cprogramming")
    // Prepare the error template
    errTemplate := template.Must(template.ParseFiles("error_template.html"))
    outTemplate := template.Must(template.ParseFiles("output_template.html"))

    // Check if the user is authenticated
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    run_result, score := RunSolution(session.Values["userid"].(string))
    if score == -1 { // Run was interrupted by a signal
        run_result = "Did not finish correctly"
    }else{
        run_result = "Finished with score: "+strconv.Itoa(score)
    }

    // If the score is an improvement, update it
    crt_score := session.Values["score"].(int)
    if score > 0 && (score < crt_score || crt_score < 0) {
        err := UpdateScore(session.Values["userid"].(string), score)
        if err != nil {
            data := map[string]interface{}{
                "Message": "Error updating score in DB. Contact admin victor[dot]cionca[at]mtu[dot]ie",
                "Error": err.Error(),
            "Link": "/static/submit.html",
            }
            errTemplate.Execute(w, data)
            return
        }
        session.Values["score"] = score
        session.Save(r, w)
        run_result += "\nBest score updated."
    }

    data := map[string]interface{}{
        "Message": run_result,
    }

    outTemplate.Execute(w, data)
    return
}

func main(){
    // Initialise PRNG
    rand.Seed(1) // TODO use time.Now().UnixNano() as seed

    // Open database
    var err error
    userDb, err = sql.Open("sqlite3", userDbFile)
    if  err != nil {
        log.Fatal(err)
    }

    // Create the router
    rt := mux.NewRouter()

    rt.HandleFunc("/", func(w http.ResponseWriter, r *http.Request){
        // TODO: if the user is already authenticated, load dashbooard
        fmt.Printf("Accessing with %s: %s\n", r.Method, r.URL.Path)
        http.ServeFile(w, r, "static/index.html")
    })

    // Login function
    rt.HandleFunc("/login", HandleLogin).Methods("POST")

    // Logout function
    rt.HandleFunc("/logout", HandleLogout)

    // Registration function
    rt.HandleFunc("/register", HandleRegistration).Methods("POST")

    // Verification function
    rt.HandleFunc("/verification/{user_id}", HandleVerification).Methods("GET")

    // Dashboard
    rt.HandleFunc("/static/dashboard.html", HandleDashboard)

    // Submission
    rt.HandleFunc("/static/submit.html", HandleSubmit)
    rt.HandleFunc("/upload", HandleUpload).Methods("POST")
    rt.HandleFunc("/compile", HandleCompile).Methods("POST")
    rt.HandleFunc("/run", HandleRun).Methods("POST")

    // Leaderboard function
    rt.HandleFunc("/leaderboard", HandleLeaderboard)


    rt.PathPrefix("/static/").Handler(http.StripPrefix("/static/",
                                      http.FileServer(http.Dir("static/"))))

    http.ListenAndServe(":8080", rt)
}
