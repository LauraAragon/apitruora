package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"

	"database/sql"

	_ "github.com/lib/pq"

	"reflect"
)

var htmltitle string
var htmllogo string

type Response struct {
	Host            string      `json:"host"`
	Port            int         `json:"port"`
	Protocol        string      `json:"protocol"`
	IsPublic        bool        `json:"isPublic"`
	Status          string      `json:"status"`
	StartTime       int64       `json:"startTime"`
	TestTime        int64       `json:"testTime"`
	EngineVersion   string      `json:"engineVersion"`
	CriteriaVersion string      `json:"criteriaVersion"`
	Endpoints       []Endpoints `json:"endpoints"`
}
type Endpoints struct {
	IPAddress         string `json:"ipAddress"`
	ServerName        string `json:"serverName"`
	StatusMessage     string `json:"statusMessage"`
	Grade             string `json:"grade"`
	GradeTrustIgnored string `json:"gradeTrustIgnored"`
	HasWarnings       bool   `json:"hasWarnings"`
	IsExceptional     bool   `json:"isExceptional"`
	Progress          int    `json:"progress"`
	Duration          int    `json:"duration"`
	Delegation        int    `json:"delegation"`
}
type DomainInfo struct {
	Servers          []DomainServer `json:"servers"`
	ServersChanged   bool           `json:"servers_changed"`
	SslGrade         string         `json:"ssl_grade"`
	PreviousSslGrade string         `json:"previous_ssl:grade"`
	Logo             string         `json:"logo"`
	Title            string         `json:"title"`
	IsDown           bool           `json:"is_down"`
}
type DomainServer struct {
	Address  string `json:"address"`
	SslGrade string `json:"ssl_grade"`
	Country  string `json:"country"`
	Owner    string `json:"owner"`
}
type LogoResponse struct {
	URL   string  `json:"url"`
	Icons []Icons `json:"icons"`
}
type Icons struct {
	URL     string      `json:"url"`
	Width   int         `json:"width"`
	Height  int         `json:"height"`
	Format  string      `json:"format"`
	Bytes   int         `json:"bytes"`
	Error   interface{} `json:"error"`
	Sha1Sum string      `json:"sha1sum"`
}
type History struct {
	Dominios []string `json:"items"`
}

func getSSLandServers(domain string) []byte {

	response, err := http.Get("https://api.ssllabs.com/api/v3/analyze?host=" + domain)

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	//getting title from html
	getTitle(domain)

	//getting logo from html
	getLogo(domain)
	// Make HTTP GET request

	return responseData
}

func getTitle(domain string) {
	response2, err2 := http.Get("https://" + domain)
	if err2 != nil {
		log.Fatal(err2)
	}
	defer response2.Body.Close()

	// Get the response body as a string
	dataInBytes, err2 := ioutil.ReadAll(response2.Body)
	pageContent := string(dataInBytes)

	// Find a substr
	titleStartIndex := strings.Index(pageContent, "<title>")
	if titleStartIndex == -1 {
		htmltitle = "No title element found"
		os.Exit(0)
	}
	titleStartIndex += 7

	// Find the index of the closing tag
	titleEndIndex := strings.Index(pageContent, "</title>")
	if titleEndIndex == -1 {
		htmltitle = "No closing tag for title found."
		os.Exit(0)
	}

	pageTitle := []byte(pageContent[titleStartIndex:titleEndIndex])
	htmltitle = string(pageTitle)
}

func getLogo(domain string) {

	response, err := http.Get("https://besticon-demo.herokuapp.com/allicons.json?url=" + domain)

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	var info LogoResponse
	json.Unmarshal(responseData, &info)
	icons := info.Icons
	htmllogo = icons[0].URL
}

func compareSSLGrades(array []DomainServer) string {

	var grade string
	for a := 0; a < len(array); a++ {
		if array[a].SslGrade == "A+" {
			grade = "A+"
		}
	}

	for b := 0; b < len(array); b++ {
		if array[b].SslGrade == "A" {
			grade = "A"
		}
	}

	for c := 0; c < len(array); c++ {
		if array[c].SslGrade == "B" {
			grade = "B"
		}
	}

	for d := 0; d < len(array); d++ {
		if array[d].SslGrade == "C" {
			grade = "C"
		}
	}

	for e := 0; e < len(array); e++ {
		if array[e].SslGrade == "D" {
			grade = "D"
		}
	}

	for f := 0; f < len(array); f++ {
		if array[f].SslGrade == "E" {
			grade = "E"
		}
	}

	for g := 0; g < len(array); g++ {
		if array[g].SslGrade == "F" {
			grade = "F"
		}
	}

	return grade

}

func getStatus(resp Response) bool {
	var status bool
	if resp.Status == "READY" {
		status = false
	}

	if resp.Status == "ERROR" {
		status = true
	}
	return status
}

func AreEqualJSON(s1, s2 string) (bool, error) {
	var o1 interface{}
	var o2 interface{}

	var err error
	err = json.Unmarshal([]byte(s1), &o1)
	if err != nil {
		return false, fmt.Errorf("Error mashalling string 1 :: %s", err.Error())
	}
	err = json.Unmarshal([]byte(s2), &o2)
	if err != nil {
		return false, fmt.Errorf("Error mashalling string 2 :: %s", err.Error())
	}

	return reflect.DeepEqual(o1, o2), nil
}

func decodeJSON(data []byte) string {
	var response Response
	json.Unmarshal(data, &response)
	endpoints := response.Endpoints
	var serverInformation []DomainServer

	for i := 0; i < len(endpoints); i++ {
		var c, o string
		resultWhoIs, err := whois.Whois(response.Host)
		if err == nil {
			parseWhoIs, err2 := whoisparser.Parse(resultWhoIs)
			if err2 == nil {
				c = parseWhoIs.Admin.Country
				o = parseWhoIs.Admin.Organization
			}
		}

		server := DomainServer{
			Address:  endpoints[i].IPAddress,
			SslGrade: endpoints[i].Grade,
			Country:  c,
			Owner:    o,
		}
		serverInformation = append(serverInformation, server)
	}

	ssl := compareSSLGrades(serverInformation)
	status := getStatus(response)
	previousssl := selectGradeFromTable(response.Host)
	change := checkJSONchanges(serverInformation, selectJsonInfoFromTable(response.Host))

	info := DomainInfo{
		Servers:          serverInformation,
		ServersChanged:   change,
		SslGrade:         ssl,
		PreviousSslGrade: previousssl,
		Logo:             htmllogo,
		Title:            htmltitle,
		IsDown:           status,
	}

	encode, _ := json.MarshalIndent(info, "", "  ")
	insertRowToTable(response.Host, info.SslGrade, len(info.Servers), time.Now().String(), string(encode))
	return string(encode)
}

func checkJSONchanges(s1, s2 []DomainServer) bool {
	j1, _ := json.Marshal(s1)
	j2, _ := json.Marshal(s2)
	c1 := string(j1)
	fmt.Println("-------------------------------------------")
	fmt.Println(c1)
	c2 := string(j2)
	fmt.Println(c2)
	fmt.Println("-------------------------------------------")
	out, _ := AreEqualJSON(c1, c2)
	return out
}

func requestFirstEndpoint(w http.ResponseWriter, r *http.Request) {
	val := chi.URLParam(r, "domain")
	fmt.Fprintf(w, decodeJSON(getSSLandServers(val)))
}

func requestSecondEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, selectRowFromTable())
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "If you want to go to servers info, add /servers to the URL, if you want to go to consult history, add /history to the URL.")
}

func askForDomain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "add '/' and the domain you want to consult to the URL")
}

func insertRowToTable(domain, sslgrade string, serversnumber int, time string, jsonInfo string) {
	db, err := sql.Open("postgres", "postgresql://maxroach@144.217.243.174:26257/apitruora?sslmode=disable")
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	fmt.Println("INSERT INTO serversinfo (dominio, sslgrade, serversnumber, time, jsoninfo) VALUES ('" + domain + "','" + sslgrade + "'," + strconv.Itoa(serversnumber) + ",'" + time + "','" + jsonInfo + "')")
	if _, err := db.Exec(
		"INSERT INTO serversinfo (dominio, sslgrade, serversnumber, time, jsoninfo) VALUES ('" + domain + "','" + sslgrade + "'," + strconv.Itoa(serversnumber) + ",'" + time + "','" + jsonInfo + "')"); err != nil {
		log.Fatal(err)
	}
}

func selectRowFromTable() string {
	db, err := sql.Open("postgres", "postgresql://maxroach@144.217.243.174:26257/apitruora?sslmode=disable")
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	rows, err := db.Query("SELECT dominio FROM apitruora.serversinfo")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var dominios []string

	for rows.Next() {
		var dominio string
		if err := rows.Scan(&dominio); err != nil {
			log.Fatal(err)
		}

		dominios = append(dominios, dominio)
	}

	history := History{
		Dominios: dominios,
	}

	encode, _ := json.MarshalIndent(history, "", "  ")
	return string(encode)
}

func selectGradeFromTable(dominio string) string {

	db, err := sql.Open("postgres", "postgresql://maxroach@144.217.243.174:26257/apitruora?sslmode=disable")
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	fmt.Println("SELECT sslgrade FROM apitruora.serversinfo WHERE dominio='" + dominio + "'")
	rows, err := db.Query("SELECT sslgrade FROM apitruora.serversinfo WHERE dominio='" + dominio + "'")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var grados []string

	for rows.Next() {
		var grado string
		if err := rows.Scan(&grado); err != nil {
			log.Fatal(err)
		}

		grados = append(grados, grado)
	}

	if len(grados) == 0 {
		return " "
	}

	return grados[len(grados)-1]

}

func selectJsonInfoFromTable(dominio string) []DomainServer {

	db, err := sql.Open("postgres", "postgresql://maxroach@144.217.243.174:26257/apitruora?sslmode=disable")
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	fmt.Println("SELECT jsoninfo FROM apitruora.serversinfo WHERE dominio='" + dominio + "'")
	rows, err := db.Query("SELECT jsoninfo FROM apitruora.serversinfo WHERE dominio='" + dominio + "'")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var grados []string

	for rows.Next() {
		var grado string
		if err := rows.Scan(&grado); err != nil {
			log.Fatal(err)
		}

		grados = append(grados, grado)
	}

	if len(grados) == 0 {
		fmt.Println("*************************retorno null********************")
		return nil
	}

	js := grados[len(grados)-1]
	fmt.Println(js + "************************************")

	var domInfo DomainInfo
	err2 := json.Unmarshal([]byte(js), domInfo)
	fmt.Println(err2)
	fmt.Println("ññññññññññññññññññññññññññññññ")
	fmt.Printf("%+v\n", domInfo)
	fmt.Println("ññññññññññññññññññññññññññññññ")

	return domInfo.Servers

	////////////////////
}

func main() {

	fmt.Println("Starting server on port :3003")
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/", homePage)
	r.Route("/servers", func(r chi.Router) {
		r.Get("/{domain}", requestFirstEndpoint)
		r.Get("/", askForDomain)
	})
	r.Get("/history", requestSecondEndpoint)
	//	r.Route("/history", func(r chi.Router) {
	//	r.Get("/", requestSecondEndpoint)
	//})

	err := http.ListenAndServe(":3003", r)
	if err != nil {
		fmt.Println("ListenAndServe:", err)
	}
}
