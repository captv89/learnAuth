# Stage 1
# Use an official Go runtime as the base image
FROM golang:1.21.1-alpine3.18 as builder
# Set the working directory in the container
WORKDIR /app
# Copy your application source code into the container
COPY . .
# Build your Go application inside the container
RUN apk add build-base # Getting the GCC compiler
RUN CGO_ENABLED=1 go install github.com/mattn/go-sqlite3 # Installing the sqlite3 driver with CGO
RUN go build -o learnAuth .

# Stage 2
# Use an official Alpine runtime as the base image
FROM alpine:3.18.3 as final
# Set the working directory in the container
WORKDIR /app
# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/learnAuth .
# Expose the port your application listens on
EXPOSE 8080
# Run the binary program produced by `go install`
CMD ["./learnAuth"]
