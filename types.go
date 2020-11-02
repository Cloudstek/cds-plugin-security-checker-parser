package main

type advisory struct {
	title string
	link  string
	cve   string
}

type vulnerablePackage struct {
	version    string
	advisories []advisory
}
