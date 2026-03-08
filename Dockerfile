# Test SSH target for deploy.sh (PhotonOS - matches vCenter environment)
#
# Build:  docker build -t ssh-door-test .
# Run:    docker run -d -p 2222:22 --name ssh-test ssh-door-test
# Deploy: ./deploy.sh -h localhost -p backdoorpass -s testpassword -P 2222
# Verify: ssh root@localhost -p 2222  (use backdoorpass)
# Creds:  docker exec ssh-test cat /var/cache/ldconfig/aux-cache.log | ./creds.sh /dev/stdin
# Shell:  docker exec -it ssh-test bash
# Clean:  docker rm -f ssh-test && docker rmi ssh-door-test

FROM photon:5.0

RUN tdnf install -y \
    openssh \
    Linux-PAM-devel \
    gcc \
    shadow \
    && tdnf clean all \
    && mkdir -p /var/run/sshd \
    && ssh-keygen -A \
    && echo 'root:testpassword' | chpasswd \
    && sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
