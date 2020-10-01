# r2docker
# ========
#
# Requires 1GB of free disk space
#
# Build docker image with:
# $ docker build -t r2docker:latest .
#
# Run the docker image:
# $ docker images
# $ export DOCKER_IMAGE_ID=$(docker images --format '{{.ID}}' -f 'label=r2docker')
# $ docker run -ti --cap-drop=ALL r2docker:latest
#
# Once you quit the bash session get the container id with:
# $ docker ps -a | grep bash
#
# To get into that shell again just type:
# $ docker start -ai <containedid>
#
# To share those images:
# $ docker export <containerid> | xz > container.xz
# $ xz -d < container.xz | docker import -
#
#
# If you willing to debug a program within Docker, you should run it with CAP_SYS_PTRACE:
#
# $ docker run -it --cap-drop=ALL --cap-add=SYS_PTRACE r2docker:latest
# $ r2 -d /bin/true
#

# Using debian 10 as base image.
FROM debian:10

# Label base
LABEL r2docker latest

# Radare version
ARG R2_VERSION=master
# R2pipe python version
ARG R2_PIPE_PY_VERSION=1.4.2

ENV R2_VERSION ${R2_VERSION}
ENV R2_PIPE_PY_VERSION ${R2_PIPE_PY_VERSION}

RUN echo -e "Building versions:\n\
  R2_VERSION=$R2_VERSION\n\
  R2_PIPE_PY_VERSION=${R2_PIPE_PY_VERSION}"

# Build rizin in a volume to minimize space used by build
VOLUME ["/mnt"]

# Install all build dependencies
# Install bindings
# Build and install rizin on master branch
# Remove all build dependencies
# Cleanup
RUN DEBIAN_FRONTEND=noninteractive dpkg --add-architecture i386 && \
  apt-get update && \
  apt-get install -y \
  curl \
  wget \
  gcc \
  git \
  bison \
  pkg-config \
  make \
  glib-2.0 \
  libc6:i386 \
  libncurses5:i386 \
  libstdc++6:i386 \
  gnupg2 \
  python-pip && \
  pip install rzpipe=="$R2_PIPE_PY_VERSION" && \
  cd /mnt && \
  git clone -b "$R2_VERSION" -q --depth 1 https://github.com/rizinorg/rizin.git && \
  cd rizin && \
  ./configure && \
  make && \
  make install && \
  apt-get install -y xz-utils && \
  apt-get remove --purge -y \
  bison \
  python-pip \
  glib-2.0 && \
  apt-get autoremove --purge -y && \
  apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create non-root user
RUN useradd -m r2 && \
  adduser r2 sudo && \
  echo "r2:r2" | chpasswd

# Initilise base user
USER r2
WORKDIR /home/r2
ENV HOME /home/r2

# Setup rz-pm
RUN rz-pm init && \
  rz-pm update && \
  chown -R r2:r2 /home/r2/.config

# Base command for container
CMD ["/bin/bash"]
