NAME = plugin-security-checker-parser
OUTDIR = build

$(NAME)-linux-amd64:
	GOOS=linux GOARCH=amd64 ${GOROOT}/bin/go build -o $(OUTDIR)/$(NAME)-linux-amd64