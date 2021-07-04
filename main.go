package main

import (
	"database/sql"

	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/context"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID          int
	FirstName   string    `json:"firstname" validate:"required, gte=3"`
	LastName    string    `json:"lastname" validate:"required, gte=3"`
	Email       string    `json:"email"`
	Password    string    `json:"password"`
	CreatedDate time.Time `json:"createdDate"`
}

type Claims struct {
	User
	jwt.StandardClaims
}

// var tpl = template.Must(template.ParseGlob("../templates/*.html"))
// var errtpl = template.Must(template.ParseGlob("../templates/errpages/*.html"))

//go:embed templates
var tplPages embed.FS

//go:embed templates/errpages
var errTplPages embed.FS

var jwtKey = []byte("my_secret_key")

func dbConn() (db *sql.DB) {
	dbDriver := os.Getenv("DB_DRIVER")
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	fmt.Println(dbDriver, dbUser, dbPass, dbName)
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@tcp(127.0.0.1:3306)/"+dbName+"?parseTime=true")
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("DB Connected!!")
	return db
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// tpl.ExecuteTemplate(w, "index.html", nil)
	tmpl, err := template.ParseFS(tplPages, "templates/index.html")
	if err != nil {
		log.Fatal("Error loading index template: ", err)
	}
	tmpl.Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		db := dbConn()
		email := r.FormValue("email")
		password := r.FormValue("password")

		fmt.Printf("%s, %s\n", email, password)

		// Validate form input
		if strings.Trim(email, " ") == "" || strings.Trim(password, " ") == "" {
			fmt.Println("Parameter's can't be empty")
			http.Redirect(w, r, "/login", http.StatusMovedPermanently)
			return
		}

		checkUser, err := db.Query("SELECT id, createdDate, password, firstname, lastname, email FROM user WHERE email=?", email)

		if err != nil {
			panic(err.Error())
		}
		user := User{}
		for checkUser.Next() {
			var id int
			var password, firstName, lastName, email string
			var createdDate time.Time
			err = checkUser.Scan(&id, &createdDate, &password, &firstName, &lastName, &email)
			if err != nil {
				panic(err.Error())
			}
			user.ID = id
			user.FirstName = firstName
			user.LastName = lastName
			user.Email = email
			user.Password = password
			user.CreatedDate = createdDate
		}

		errf := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if errf != nil && errf == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
			fmt.Println(errf)
			http.Redirect(w, r, "/login", http.StatusMovedPermanently)
		} else {
			expirationTime := time.Now().Add(5 * time.Minute)
			// Create the JWT claims, which includes the username and expiry time
			claims := &Claims{
				User: user,
				StandardClaims: jwt.StandardClaims{
					// In JWT, the expiry time is expressed as unix milliseconds
					ExpiresAt: expirationTime.Unix(),
				},
			}

			// Declare the token with the algorithm used for signing, and the claims
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			// Create the JWT string
			tokenString, err := token.SignedString(jwtKey)
			if err != nil {
				log.Println("Error creating JWT return", err)
				// If there is an error in creating the JWT return an internal server error
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			fmt.Println("Token:", tokenString)

			// Finally, we set the client cookie for "token" as the JWT we just generated
			// we also set an expiry time which is the same as the token itself
			http.SetCookie(w, &http.Cookie{
				Name:    "token",
				Value:   tokenString,
				Expires: expirationTime,
			})

			http.Redirect(w, r, "/dashboard", http.StatusPermanentRedirect)
			return
		}
	} else {
		// tpl.ExecuteTemplate(w, "Login", nil)
		tmpl, err := template.ParseFS(tplPages, "templates/login.html")
		if err != nil {
			log.Fatal("Error loading login template:", err)
		}
		tmpl.Execute(w, nil)
	}

}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// tpl.ExecuteTemplate(w, "Register", nil)
	tmpl, err := template.ParseFS(tplPages, "templates/register.html")
	if err != nil {
		log.Fatal("Error loading register template:", err)
	}
	tmpl.Execute(w, nil)
}

func registerProcess(w http.ResponseWriter, r *http.Request) {
	db := dbConn()
	if r.Method == "POST" {
		firstName := r.FormValue("FirstName")
		lastName := r.FormValue("LastName")
		email := r.FormValue("email")
		fmt.Printf("%s, %s, %s\n", firstName, lastName, email)

		password, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println(err)
			// tpl.ExecuteTemplate(w, "Register", err)
			tmpl, err := template.ParseFS(tplPages, "templates/register.html")
			if err != nil {
				log.Fatal("Error loading register template:", err)
			}
			tmpl.Execute(w, err)
		}

		dt := time.Now()

		createdDateString := dt.Format("2006-01-02 15:04:05")

		createdDate, err := time.Parse("2006-01-02 15:04:05", createdDateString)
		if err != nil {
			log.Fatal("Error converting the time:", err)
		}

		_, err = db.Exec("INSERT INTO user(firstname, lastname,email,password,createdDate) VALUES(?,?,?,?,?)", firstName, lastName, email, password, createdDate)
		if err != nil {
			fmt.Println("Error when inserting: ", err.Error())
			panic(err.Error())
		}
		log.Println("=> Inserted: First Name: " + firstName + " | Last Name: " + lastName)

		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	}

}

func Dashboard(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			log.Println("No cookie set error:", err)
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			// errtpl.ExecuteTemplate(w, "401.html", nil)
			tmpl, err := template.ParseFS(errTplPages, "401.html")
			if err != nil {
				log.Fatal("Error loading 401 template:", err)
			}
			tmpl.Execute(w, nil)
			return
		}
		// For any other type of error, return a bad request status
		log.Println("Any other cookie error:", err)
		w.WriteHeader(http.StatusBadRequest)
		// errtpl.ExecuteTemplate(w, "400.html", nil)
		tmpl, err := template.ParseFS(errTplPages, "400.html")
		if err != nil {
			log.Fatal("Error loading 400 template:", err)
		}
		tmpl.Execute(w, nil)
		return
	}

	// Get the JWT string from the cookie
	tknStr := c.Value

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			log.Println("error invalid signature:", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		log.Println("Error returning jwtKey:", err)
		w.WriteHeader(http.StatusBadRequest)
		// errtpl.ExecuteTemplate(w, "400.html", nil)
		tmpl, err := template.ParseFS(errTplPages, "400.html")
		if err != nil {
			log.Fatal("Error loading 400 template:", err)
		}
		tmpl.Execute(w, nil)
		return
	}
	if !tkn.Valid {
		log.Println("token not valid:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Finally, return the welcome message to the user, along with their
	// username given in the token
	// tpl.Execute(w, claims.User)
	tmpl, err := template.ParseFS(tplPages, "templates/dashboard.html")
	if err != nil {
		log.Fatal("Error loading dashboard template:", err)
	}
	tmpl.Execute(w, claims.User)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Logging out sessionnnnn!")
	c, err := r.Cookie("token")
	if err != nil {
		log.Fatal("error getting cookie")
		http.Redirect(w, r, "/login", http.StatusPermanentRedirect)
	}
	d := http.Cookie{
		Name:   c.Name,
		MaxAge: -1} // setting the maxAge < 0 deletes the cookie
	http.SetCookie(w, &d)
	http.Redirect(w, r, "/login", http.StatusPermanentRedirect)

}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logouth", logoutHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/registerprocess", registerProcess)
	http.HandleFunc("/dashboard", Dashboard)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server started on: http://localhost:8000")
	err = http.ListenAndServe(":8000", context.ClearHandler(http.DefaultServeMux)) // context to prevent memory leak
	if err != nil {
		log.Fatal(err)
	}

}
