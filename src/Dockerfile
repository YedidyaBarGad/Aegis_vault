# Stage 1: The Build Stage
FROM golang:1.24-alpine AS builder

# Set the working directory inside the container.
WORKDIR /app

# Copy the go.mod and go.sum files first to leverage Docker's cache.
# If these files don't change, this layer won't be rebuilt.
COPY go.mod go.sum ./

# Download all the dependencies.
RUN go mod download

# Copy the rest of the application's source code.
COPY . .

# Set environment variables to disable Go modules' use of the browser
# and to ensure the application runs in a non-interactive mode.
ENV BROWSER=none

# Build the Go application binary.
# The `-o main` flag names the output executable 'main'.
# The `-ldflags "-s -w"` flags reduce the size of the binary by
# stripping debugging information and symbol tables.
RUN go build -tags=web -o main -ldflags "-s -w" .

# Stage 2: The Final, Minimal Stage
# We use a minimal Alpine Linux image to run the application, which keeps the image size small.
FROM alpine:latest

# Set the working directory for the final container.
WORKDIR /app

# Copy the built binary from the `builder` stage.
COPY --from=builder /app/main .

# Copy the `templates` and `users_data` directories from the builder stage.
# These directories contain the HTML files and user vault data.
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/users_data ./users_data

# Expose the port on which the application will listen.
EXPOSE 8080

# The command to run the application.
CMD ["./main"]
