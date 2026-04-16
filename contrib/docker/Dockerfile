FROM debian:bullseye-slim
RUN apt update && apt install -y curl
RUN curl -fLs -o /usr/local/bin/aws-vault https://github.com/envato/aws-vault/releases/latest/download/aws-vault-linux-amd64 && chmod 755 /usr/local/bin/aws-vault
ENV AWS_VAULT_BACKEND=file
ENTRYPOINT ["/usr/local/bin/aws-vault"]

# Example usage:
#     docker build -t aws-vault .
#     docker run -it -e COLUMNS=$(tput cols) -v ~/.aws/config:/root/.aws/config -v ~/.awsvault:/root/.awsvault aws-vault
