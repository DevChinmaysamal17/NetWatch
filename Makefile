build:
	go build -o netwatch .

run:
	go build -o netwatch . && sudo ./netwatch
