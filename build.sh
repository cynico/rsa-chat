#!/bin/sh -e

if [ ! -e './server/server.go' ] || [ ! -e './client/client.go' ] || [ ! -e './attack/attack.go' ]; then
	echo "You must be inside the assignment directory, where the script is located"
	exit 1
fi

MAINDIR=$(pwd)

for i in attack server client; do

	cd $MAINDIR/$i
	go mod tidy
	GOOS=linux GOARCH=amd64 CGO_ENBALED=0 go build -o ../bin/$i $i.go

done