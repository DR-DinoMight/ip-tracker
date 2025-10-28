# Stage 1: Build the Go application
FROM golang:alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY main.go ./

# Build the application as a static binary
# CGO_ENABLED=0 is important for creating a static binary without C dependencies
# -ldflags="-w -s" strips debugging information to make the binary smaller
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o ip-tracker .

# Stage 2: Create the final, minimal image from "scratch"
# "scratch" is a completely empty image
FROM scratch

WORKDIR /

# Copy the compiled binary from the builder stage
COPY --from=builder /app/ip-tracker /ip-tracker

# Copy CA certificates needed for HTTPS calls (to Resend)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Create a non-root user (optional but good practice)
# Although scratch has no shell to create a user, Docker can run the binary as a specified UID/GID
# We will define this in the docker-compose.yml file (user: "1000:1000")

# Expose the port the application will listen on
EXPOSE 8080

# The command to run the application
ENTRYPOINT ["/ip-tracker"]
