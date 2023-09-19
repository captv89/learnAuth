run:
	go run .

build:
	go build -o bin/learnAuth -v

prod-run:
	./bin/learnAuth

docker-build:
	docker build -t learn-auth .

docker-run:
	docker run -p 8080:8080 learn-auth

docker-run-detached:
	docker run -d -p 8080:8080 learn-auth