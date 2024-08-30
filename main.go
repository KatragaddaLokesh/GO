package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	"github.com/lib/pq"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"
)

type RouteResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

type Creds struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type claims struct {
	Username string `json:"username,omitempty"`
	XataID   string `json:"xata_id"`
	jwt.RegisteredClaims
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type UserResponse struct {
	XataID   string `json:"xata_id"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

type Project struct {
	XataID          string   `json:"xata_id,omitempty"`
	UserID          string   `json:"userid,omitempty"`
	Name            string   `json:"name,omitempty"`
	RepoUrl         string   `json:"repo_url,omitempty"`
	SiteUrl         string   `json:"site_url,omitempty"`
	Description     string   `json:"description,omitempty"`
	Dependencies    []string `json:"dependencies,omitempty"`
	DevDependencies []string `json:"dev_dependencies,omitempty"`
	Status          string   `json:"status,omitempty"`
}
type app struct {
	DB     *sql.DB
	JWTKey []byte
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Err loading .env file", err)
	}

	var loaderr error
	userSchema, loaderr := loadSchema("schemas/user.json")
	if loaderr != nil {
		log.Fatalf("Error Loading Error: %v", loaderr)
	}
	projectSchema, loaderr := loadSchema("schemas/user.json")
	if loaderr != nil {
		log.Fatalf("Error Loading Error: %v", loaderr)
	}

	JWTKey := []byte(os.Getenv("JSW_SECRET_KEY"))
	if len(JWTKey) == 0 {
		log.Fatal("JWT env is not set up")
	}
	conn := os.Getenv("XATA_PSQL_URL")
	if len(conn) == 0 {
		log.Fatal("XATA_PSQL_URL is not set", err)
	}

	db, err := sql.Open("postgres", conn)
	if err != nil {
		log.Fatal("Failed To Connect To DB", err)
	}
	defer db.Close()

	app := &app{
		DB: db,
	}

	router := mux.NewRouter()
	srv := &http.Server{
		Addr:    ":5000",
		Handler: router,
	}

	setup(router, app, userSchema, projectSchema)

	log.Println("Listing on Port 5000")
	log.Fatal(srv.ListenAndServe())
}

func setup(router *mux.Router, app *app, userSchema, projectSchema string) {
	userChain := alice.New(middleware, validatMiddleware(userSchema))

	router.Handle("/register", userChain.ThenFunc(app.register)).Methods("Post")
	router.Handle("/login", userChain.ThenFunc(app.login)).Methods("Post")

	projectChain := alice.New(middleware, app.jwtmiddleware)
	router.Handle("/projects", projectChain.ThenFunc(app.getProjects)).Methods("Get")
	router.Handle("/projects/{xata_id}", projectChain.ThenFunc(app.getProject)).Methods("Get")
	router.Handle("/projects/{id}", projectChain.ThenFunc(app.deleteProject)).Methods("Delete")

	projectChainWithVal := projectChain.Append(validatMiddleware(projectSchema))
	router.Handle("/projects", projectChainWithVal.ThenFunc(app.createProject)).Methods("Post")
	router.Handle("/projects/{id}", projectChainWithVal.ThenFunc(app.updateProject)).Methods("Put")
}

func loadSchema(filepath string) (string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s%s%s\n", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func (app *app) jwtmiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if auth == "" {
			respondError(w, http.StatusUnauthorized, "No Token Provided")
			return
		}
		tokenstring := strings.TrimPrefix(auth, "Bearer")

		claims := &claims{}

		token, err := jwt.ParseWithClaims(tokenstring, claims, func(token *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				respondError(w, http.StatusUnauthorized, "Invalid Token Signature")
				return
			}
			respondError(w, http.StatusBadRequest, "Invalid Token Signature")
			return
		}

		if !token.Valid {
			respondError(w, http.StatusUnauthorized, "Invalid Token ")
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validatMiddleware(schema string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]interface{}
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				respondError(w, http.StatusBadRequest, "Invalid Payload")
				return
			}

			err = json.Unmarshal(bodyBytes, &body)
			if err != nil {
				respondError(w, http.StatusBadRequest, "Invalid Payload")
				return
			}

			schemaloader := gojsonschema.NewStringLoader(schema)

			documentLoader := gojsonschema.NewGoLoader(body)

			res, err := gojsonschema.Validate(schemaloader, documentLoader)
			if err != nil {
				respondError(w, http.StatusBadRequest, "Invalid Payload")
				return
			}

			if !res.Valid() {
				var errs []string

				for _, err := range res.Errors() {
					errs = append(errs, err.String())
				}
				respondError(w, http.StatusBadRequest, strings.Join(errs, " , "))
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
		})
	}
}

func respondError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{
		Message: msg,
	})
}

func (app *app) generateToken(username, xataId string) (string, error) {
	experation := time.Now().Add(5 * time.Hour)
	claims := &claims{
		Username: username,
		XataID:   xataId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(experation),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(app.JWTKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil

}

func (app *app) register(w http.ResponseWriter, r *http.Request) {
	var creds Creds

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid Valid Request")
		return
	}

	hashpass, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error Hashing Password")
		return
	}
	var xata_id string
	err = app.DB.QueryRow("INSERT INTO \"users\" (username,password) values ($1, $2) returning xata_id", creds.Username, string(hashpass)).Scan(&xata_id)
	if err != nil {
		log.Print(err)
		respondError(w, http.StatusInternalServerError, "Error Creating Users")
		return
	}

	token, err := app.generateToken(creds.Username, xata_id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error Generating token")
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{
		XataID:   xata_id,
		Username: creds.Username,
		Token:    token,
	})
}

func (app *app) login(w http.ResponseWriter, r *http.Request) {
	var creds Creds

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid Valid Request")
		return
	}

	var store Creds
	var xataId string

	err = app.DB.QueryRow("Select xata_id, username password from \"users\" where username = $1", creds.Username).Scan(&xataId, &store.Username, &store.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusUnauthorized, "No User Found")
			return
		}
		log.Print(err)
		respondError(w, http.StatusInternalServerError, "Invalid Req")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(store.Password), []byte(creds.Password))
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid Password")
	}

	token, err := app.generateToken(creds.Username, xataId)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error Generating token")
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{
		XataID:   xataId,
		Username: creds.Username,
		Token:    token,
	})
}

func (app *app) createProject(w http.ResponseWriter, r *http.Request) {
	var projects Project

	err := json.NewDecoder(r.Body).Decode(&projects)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid req Payload")
	}

	claims := r.Context().Value("claims").(*claims)
	userID := claims.XataID

	var xataID string
	err = app.DB.QueryRow(
		"Insert into projects (\"user\", names, repo_url, sites_url, description, dependencies, dev_dependencies, status) values($1,$2,$3,$4,$5,$6,$7,$8) returning xata_id", userID, projects.Name, projects.RepoUrl, projects.SiteUrl, projects.Description, pq.Array(projects.Dependencies),
		pq.Array(projects.DevDependencies), projects.Status).Scan(&xataID)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error Creating Project")
		return
	}

	projects.XataID = xataID
	projects.UserID = userID
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

func (app *app) updateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["xata_id"]

	claims := r.Context().Value("claims").(*claims)
	userID := claims.XataID

	var storeUserID string
	var Project Project
	err := app.DB.QueryRow("Select \"users\" from project where xata_id=$1", id).Scan(&storeUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Project Not Found")
			return
		}
		respondError(w, http.StatusInternalServerError, "Error Fetching Project")
		return

	}

	if storeUserID != userID {
		respondError(w, http.StatusForbidden, "Do Not Have The Permission To Update")
		return
	}

	_, err = app.DB.Exec(
		"Update projects set name=$1,repo_url=$2,site_url=$3,description=$4,dependencies=$5, dev_dependencies=$6,status=$7 where xata_id=$8 and \"user\"=$9",
		Project.Name, Project.RepoUrl, Project.SiteUrl, Project.Description, pq.Array(Project.Dependencies), pq.Array(Project.DevDependencies), Project.Status, id, userID,
	)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error Updating Project")
		return
	}

	Project.XataID = id
	Project.UserID = userID
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(Project)
}

func (app *app) getProjects(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*claims)
	userID := claims.XataID

	rows, err := app.DB.Query("select xata_id, \"user\", name, repo_url,site_url, description, dependencies, dev_dependencies, status from project where \"user\"=$1", userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "User doesnot exist")
		return
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var project Project
		var dependencies, devDependencies []string

		err = rows.Scan(&project.XataID, &project.UserID, &project.Name, &project.RepoUrl, &project.SiteUrl, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "User doesnot exist")
			return
		}

		project.Dependencies = dependencies
		project.DevDependencies = dependencies

		projects = append(projects, project)
	}

	err = rows.Err()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error Fetching Project")
		return
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

func (app *app) getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["xata_id"]

	claims := r.Context().Value("claims").(*claims)
	userID := claims.XataID

	var project Project

	var dep, devDep []string

	err := app.DB.QueryRow("select xata_id, \"user\", name, repo_url,site_url,description, dependencies, dev_dependencies, status from project where xata_id=$1  and \"user\"=$2 ",
		id, userID).Scan(&project.XataID, &project.UserID, &project.Name, &project.RepoUrl, &project.SiteUrl, &project.Description, pq.Array(&dep), pq.Array(&devDep), &project.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusInternalServerError, "Project Not Found")
			return
		}
		respondError(w, http.StatusInternalServerError, "Error Getting Project")
		return
	}

	project.Dependencies = dep
	project.DevDependencies = devDep

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

func (app *app) deleteProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["xata_id"]

	claims := r.Context().Value("claims").(*claims)
	userID := claims.XataID

	var storeUserID string
	err := app.DB.QueryRow("Select \"users\" from project where xata_id=$1", id).Scan(&storeUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Project Not Found")
			return
		}
		respondError(w, http.StatusInternalServerError, "Error Fetching Project")
		return
	}

	if storeUserID != userID {
		respondError(w, http.StatusForbidden, "Do Not Have The Permission To Update")
		return
	}

	_, err = app.DB.Exec("Delete from projects where xata_id=$1 and \"user\"=$2", id, userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error Updating Project")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
