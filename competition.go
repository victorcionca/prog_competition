package main

import (
    "fmt"
    "log"
    "io"
    "bufio"
    "os"
    "os/exec"
    "time"
    "bytes"
    "strings"
    "strconv"
    "errors"
    "sort"
    "context"
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
    postmark "github.com/mrz1836/postmark"
)

// ----------------------------------------------------------------------------
// Containerisation
func CreateUserContainer(user_id string) (string, error) {
    // Get absolute path to the executable
    root_path, _ := os.Getwd()
    // Get the user folder
    user_folder := GetUserFolder(user_id)
    // Get the absolute path to the current folder
    out, err := exec.Command("docker",
                             "create",
                             "-v", root_path+"/"+user_folder+":/mnt",
                             "-u", "1001",
                             "--entrypoint=/mnt/hungry_monkey_static",
                             "alpine:latest").CombinedOutput()
    container_id := ""
    if err == nil {
        // Get the docker container ID and store for the user
        container_id = strings.TrimSpace(string(out))
    }

    return container_id,err
}

// ----------------------------------------------------------------------------
// The following should be configured for the competition details
const (
    userDbFile = "userdb.db"
    leaderboardTemplate = "static/leaderboard.html"
    webaddress = "http://127.0.0.1:8080"
    emailTemplate = `Dear {{ .Name }},
        Thank you for registering for the C Programming competition.
        To activate your account follow the link below:
        {{ .Link }}`
    user_folders = "user_folders"
    user_sol_file = "move_monkey.c"
    competitionBinary = "hungry_monkey_static"
)

func getCompetitionFilenames() []string {
    return []string{"hungry_monkey_nogui.c",
                    "hungry_monkey.h",
                    "config_seccomp.c",
                    "config_seccomp.h"}
}

func getCompiledCommand() *exec.Cmd {
    return exec.Command("gcc",
                        "hungry_monkey_nogui.c",
                        "move_monkey.c",
                        "config_seccomp.c",
                        "-lm",
                        "--static",
                        "-o",
                        competitionBinary)
}


type SolutionScore struct {
    MedSuccess float32
}

func CalculateScore(score SolutionScore) float32 {
    return float32(score.MedSuccess)
}

// Specific to competition binary
// Processes the output of the binary to extract the score.
// Also returns the result (-1 on error) and an error message.
func processSolutionOutput(solOut []byte) (string,SolutionScore,int) {
    var score SolutionScore
    outString := string(solOut)
    result := -1
    fields := strings.Split(strings.TrimSpace(outString), ",")
    if len(fields) == 2 {
        status := fields[0]
        if strings.Compare(status, "Success") == 0 || strings.Compare(status, "Infloop") == 0{
            tmp, _ := strconv.ParseInt(fields[1], 10, 0)
            score.MedSuccess = int(tmp)
            return "success", score, 0
        }else if strings.Compare(status, "Error") == 0{
            return "error: "+fields[1], score, -1
        }
    }
    return outString,score,result
}


// Runs the competition binary in its respective container
// Returns
//  - a message that will be displayed to the user
//  - a score
//  - a result code, -1 indicates error.
func RunSolutionSpecific(containerid string) (string, SolutionScore, int) {
    // Before starting the container, schedule its stop to prevent hangups
    go func() {
        time.Sleep(30*time.Second)
        exec.Command("docker",
                     "kill",
                     containerid).Run()
     }()

    // Start the docker container
    out, err := exec.Command("docker",
                             "start",
                             "-i",
                             containerid).CombinedOutput()
    if err == nil {
        runOut,runScore,runResult := processSolutionOutput(out)
        return runOut, runScore, runResult
    }else{
        return "error: "+string(out), SolutionScore{MedSuccess:0}, -1
    }

}


// ----------------------------------------------------------------------------

var userDb *sql.DB
var session_store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

type UserRecord struct {
    Email string
    Salt []byte
    Password string
    Name string
    Id string
    ContainerId string
    DetailedScore SolutionScore
    Score float32
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
    return GetUserFolder(userid)+"/"+user_sol_file
}

func PrepareUserFolder(userid string) error {
    userfolder := GetUserFolder(userid)
    // Create the folder
    var err error
    if err = os.Mkdir(userfolder, os.ModePerm); err != nil {
        return err
    }
    // Copy in the folder the template files
    for _, filename := range getCompetitionFilenames() {
        cmd := exec.Command("cp", user_folders+"/"+filename, userfolder+"/")
        if err = cmd.Run(); err != nil {
            return err
        }
    }

    return nil
}

func CopySourcesToUserFolder(userid string) error {
    var err error
    userfolder := GetUserFolder(userid)
    // Copy in the folder the template files
    for _, filename := range getCompetitionFilenames() {
        cmd := exec.Command("cp", user_folders+"/"+filename, userfolder+"/")
        if err = cmd.Run(); err != nil {
            return err
        }
    }

    return nil
}

// Split into C tokens
func SplitC(data []byte, atEOF bool) (int, []byte, error) {
    if atEOF {
        return 0, nil, nil
    }

    idx_par := bytes.IndexAny(data, "( \t\n\r,+-=*/%<>&|!")
    if idx_par < 0 {
        return 0, nil, nil
    }else{
        token := make([]byte, idx_par)
        copy(token, data[:idx_par])
        return idx_par+1, token, nil
    }
}

// Check the uploaded file for illegal expressions,
// such as printf, redefinition of important functions etc
func CheckUpload(file multipart.File) error {
    scanner := bufio.NewScanner(file)
    scanner.Split(SplitC)
    prev := ""
    wrd := ""
    for scanner.Scan() {
        wrd = scanner.Text()
        if strings.Compare(wrd, "printf") == 0 {
            return errors.New("You are not allowed to use printf")
        }
        if strings.Compare(wrd, "fprintf") == 0 {
            return errors.New("You are not allowed to use fprintf")
        }
        if strings.Compare(wrd, "puts") == 0 {
            return errors.New("You are not allowed to use puts")
        }
        if strings.Compare(wrd, "fputs") == 0 {
            return errors.New("You are not allowed to use fputs")
        }
        if strings.Compare(wrd, "write") == 0 {
            return errors.New("You are not allowed to use write")
        }
        if len(prev) > 0 && strings.Compare(wrd, "random") == 0 && strings.Compare(prev, "int") == 0 {
            return errors.New("Are you trying to redefine random?")
        }
        if len(prev) > 0 && strings.Compare(wrd, "srand") == 0 && strings.Compare(prev, "void") == 0 {
            return errors.New("Are you trying to redefine srand?")
        }
        if len(wrd) > 1 {
            prev = wrd
        }
    }
    // Reset the file to start
    file.Seek(0,0)

    return nil
}



func UploadFile(file multipart.File, userid string) error {
    // Create user file
    dst, err := os.Create(GetUserSolutionFile(userid))
    defer dst.Close()
    if err != nil {
        return err
    }

    // Check the uploaded file for forbidden functions etc
    if err = CheckUpload(file); err != nil {
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
    compileCommand := getCompiledCommand()
    out, err = compileCommand.CombinedOutput()
    if err != nil {
        return string(out), err
    }

    return string(out), nil
}

// Runs a solution and returns a run message (e.g. SEGFAULT), obtained score
func RunSolution(userid string, containerid string) (string, SolutionScore, int) {
    user_folder := GetUserFolder(userid)

    // Check that binary exists
    wdir, _ := os.Getwd()
    if _, err := os.Stat(wdir + "/"+user_folder+"/"+competitionBinary); errors.Is(err, os.ErrNotExist) {
        return "Solution hasn't been compiled yet!", SolutionScore{MedSuccess:0}, -1
    }

    //  Run solution
    log.Println("Running in "+GetUserFolder(userid))
    solOut, score, result := RunSolutionSpecific(containerid)
    return solOut, score, result
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
    subject := "SOFT7019 Competition: verify account"
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
    emailReq := postmark.Email{
        From:       "victor.cionca@mtu.ie",
        To:         user.Email,
        Subject:    subject,
        TextBody:   plainTextContent,
    }
    //auth := &http.Client{Transport: &postmark.AuthTransport{
    //                    Token: os.Getenv("POSTMARK_SERVER_API_TOKEN")}}
    //client := postmark.NewClient(postmark.WithClient(auth))
    client := postmark.NewClient(os.Getenv("POSTMARK_SERVER_API_TOKEN"),
                                 os.Getenv("POSTMARK_ACCOUNT_TOKEN"))
    _, err := client.SendEmail(context.Background(), emailReq)
    if err != nil {
        return err
    }
    //log.Println("Sent verification email to ", user.Name)
    return nil
}

/* --------------------------------------------------------------------------- */
// Database functions
// TODO: modify DB info for user score

func AddUser(user UserRecord) error {
    addUserSQL := "INSERT INTO users(email, salt, password, name, id, container_id, score, verified, medsuccess) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)"
    statement, err := userDb.Prepare(addUserSQL)
    if err != nil {
        return err
    }
    _, err = statement.Exec(user.Email, user.Salt, user.Password, user.Name, user.Id, "", -1, -1)
    return err
}

func SetContainerId(userid string, containerId string) error {
    setContainerSQL := "UPDATE users SET container_id =? WHERE id = ?";
    statement, err := userDb.Prepare(setContainerSQL)
    if err != nil {
        return err
    }
    _, err = statement.Exec(containerId, userid)
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

func UpdateScore(userid string, score SolutionScore) error {
    updateScoreSQL := "UPDATE users SET medsuccess =? WHERE id = ?";
    statement, err := userDb.Prepare(updateScoreSQL)
    if err != nil {
        return err
    }
    _, err = statement.Exec(score.MedSuccess, userid)
    return err
}

func GetScore(userid string) (SolutionScore, error) {
    var score SolutionScore
    getScoreSQL := "SELECT medsuccess from users WHERE id = ?";
    statement, err := userDb.Prepare(getScoreSQL)
    if err != nil {
        return score, nil
    }
    row := statement.QueryRow(userid)
    err = row.Scan(&score.MedSuccess)
    return score, err
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
    var tmp int
    user.Email = ""

    getUserSQL := "SELECT email,salt,password,name,id,container_id,score,verified,medsuccess FROM users where email == ?"
    statement, err := userDb.Prepare(getUserSQL)
    if err != nil {
        return user, nil
    }
    row := statement.QueryRow(email)
    err = row.Scan(&user.Email, &user.Salt, &user.Password, &user.Name, &user.Id,
                    &user.ContainerId, &tmp, &user.Verified, &user.DetailedScore.MedSuccess)
    if err != nil {
        return user, err
    }else{
        // Calculate the score
        user.Score = CalculateScore(user.DetailedScore)
        return user, nil
    }
}

// Get all the user records from the DB
func GetUserRecords(onlyValid bool, validScore bool) ([]UserRecord, error) {
    rows, err := userDb.Query("SELECT email,salt,password,name,id,container_id,score,verified,medsuccess FROM users")
    if err != nil {
        log.Println("Error on first select")
        return nil, err
    }
    defer rows.Close()

    var records []UserRecord
    for rows.Next() {
        var record UserRecord
        var tmp int
        err := rows.Scan(&record.Email, &record.Salt, &record.Password, &record.Name,
                         &record.Id, &record.ContainerId, &tmp, &record.Verified,
                         &record.DetailedScore.MedSuccess)
        if err != nil {
            return nil, err
        }
        record.Score = CalculateScore(record.DetailedScore)
        if onlyValid && record.Verified == 1 && (!validScore || record.Score > 0) {
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

    // Read the user records from the DB with valid scores
    userRecords, err := GetUserRecords(true, true)
    if err != nil {
        log.Println(err.Error())
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
    session.Values["containerId"] = userRecord.ContainerId
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

    // Create a folder for the user
    err := PrepareUserFolder(vars["user_id"])
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error preparing user folders. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Create user container
    containerId := ""
    containerId, err = CreateUserContainer(vars["user_id"])
    if err != nil {
        data := map[string]interface{}{
            "Message": "Error creating user container. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Error": err.Error(),
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }

    // Update user record with container id
    err = SetContainerId(vars["user_id"], containerId)
    if err != nil {
        log.Println("Could not set containerId for the user")
        data := map[string]interface{}{
            "Message": "Failed to set container id. Contact admin victor[dot]cionca[at]mtu[dot]ie",
            "Link": "/",
        }
        errTemplate.Execute(w, data)
        return
    }


    // Finally mark this user as valid
    err = ValidateUser(vars["user_id"])
    if err != nil {
        log.Println("Could not validate the user")
        data := map[string]interface{}{
            "Message": "Incorrect validation link. Contact admin victor[dot]cionca[at]mtu[dot]ie",
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

    run_result, score, result := RunSolution(session.Values["userid"].(string),
                                             session.Values["containerId"].(string))
    if result == -1 { // Run was interrupted by a signal
        run_result = "Did not finish correctly: "+run_result
    }else{
	    run_result = fmt.Sprintf("Score: %0.2f ", CalculateScore(score))
        log.Println(run_result, session.Values["email"])
    }

    // If the score is an improvement, update it
    crt_detailed_score, _ := GetScore(session.Values["userid"].(string))
    crt_score := CalculateScore(crt_detailed_score)
    new_score := CalculateScore(score)
    log.Printf("New: %0.2f Current: %0.2f", new_score, crt_score)
    if new_score > 0 && (new_score < crt_score || crt_score <= 0) {
        err := UpdateScore(session.Values["userid"].(string), score)
        if err != nil {
		log.Println("HandleRun: " + err.Error())
            data := map[string]interface{}{
                "Message": "Error updating score in DB. Contact admin victor[dot]cionca[at]mtu[dot]ie",
                "Error": err.Error(),
            "Link": "/static/submit.html",
            }
            errTemplate.Execute(w, data)
            return
        }
        session.Values["score"] = new_score
        session.Save(r, w)
        run_result += "\nBest score updated."
    }

    data := map[string]interface{}{
        "Message": run_result,
    }

    outTemplate.Execute(w, data)
    return
}

func UpdateScores() {
    // Read the user records from the DB
    userRecords, err := GetUserRecords(true, false)
    if err != nil {
        log.Fatal("Error retrieving user records: "+err.Error())
    }

    for _, user := range userRecords {
        // Copy source files to the user folder
        log.Printf("Copying source files for %s", user.Name)
        err = CopySourcesToUserFolder(user.Id)
        if err != nil {
            log.Printf("Error updating sources for %s(%s)", user.Name, user.Id)
            continue
        }
        // Compile solution
        log.Printf("Compiling source files for %s", user.Name)
        _, err = TryCompile(user.Id)
        if err != nil {
            log.Printf("Error compiling sources for %s(%s)", user.Name, user.Id)
            continue
        } 
        // Run solution
        log.Printf("Running source files for %s", user.Name)
        _, newscore, result := RunSolution(user.Id, user.ContainerId)
        if result >= 0 {
            log.Printf("Updating score of %s(%s) to %v", user.Name, user.Id, newscore)
            err = UpdateScore(user.Id, newscore)
            if err != nil {
                log.Println("Did not work:"+err.Error())
            }
        }
    }
}

// Called if we want to generate containers for all the users at once
func GenerateContainers() {
    // Read the user records from the DB
    userRecords, err := GetUserRecords(true, false)
    if err != nil {
        log.Fatal("Error retrieving user records: "+err.Error())
    }

    for _, user := range userRecords {
        // Ignore non-validated users
        if user.Verified == 0 {
            continue
        }

        log.Printf("Creating container for %s: ", user.Email)
        // Create user container
        containerId := ""
        containerId, err = CreateUserContainer(user.Id)
        if err != nil {
            log.Printf("FAIL.\nError creating user container: %s. Skipping.\n",err.Error())
            continue;
        }
        log.Printf("SUCCESS: %s\n", containerId)

        // Update user record with container id
        log.Printf("Set container ID.");
        err = SetContainerId(user.Id, containerId)
        if err != nil {
            log.Printf("FAIL: %s\n", err.Error())
            continue;
        }
        log.Printf("SUCCESS\n")
    }
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

    cmdArgs := os.Args
    if len(cmdArgs) > 1 {
        if cmdArgs[1] == "update" {
            log.Println("Update DB")
            UpdateScores()
            return
        }
        if cmdArgs[1] == "containers" {
            log.Println("Creating containers")
            GenerateContainers()
            return
        }
    }

    log.Println("Starting server")

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
