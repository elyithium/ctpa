docker
sudo apt install podman-docker
docker pull webgoat/webgoat
docker run -it -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat

dast
# Build the Docker image
docker build -t dynascan .

# Run the Docker container
docker run --network="host" -it --rm dynascan



