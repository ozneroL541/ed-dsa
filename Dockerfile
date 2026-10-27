# syntax=docker/dockerfile:1

FROM golang:1.27.1 AS tests
WORKDIR /app
# Cache dependencies to speed up builds
COPY go.* ./

#RUN go mod download
# Copy the Makefiles
COPY Makefile ./

# Copy the KAT tests
COPY kat.json ./
# Copy the source code
COPY *.go ./

# Build the application
ENTRYPOINT ["make", "test"]
