# rizin docker
# ========
#
# Requires 400MB of free disk space
#
# Build docker image with:
# $ docker build -t rizin:latest .
# To enable rz-asm plugins based on binutils, pass '--build-arg with_ARCH_as=1' to the build command.
# Supported ARCHs are arm32, arm64, ppc. Each ARCH should be passed in a separate '--build-arg'.
#
# Run the docker image:
# $ docker images
# $ export DOCKER_IMAGE_ID=$(docker images --format '{{.ID}}' -f 'label=rizin')
# $ docker run -ti --cap-drop=ALL rizin:latest
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
# $ docker run -it --cap-drop=ALL --cap-add=SYS_PTRACE rizin:latest
# $ rizin -d /bin/true
#

FROM debian:10

# rz-pipe python version
ARG RZ_PIPE_PY_VERSION=master
# rz-ghidra version
ARG RZ_GHIDRA_VERSION=dev

ARG with_arm32_as
ARG with_arm64_as
ARG with_ppc_as

ENV RZ_PIPE_PY_VERSION ${RZ_PIPE_PY_VERSION}
ENV RZ_GHIDRA_VERSION ${RZ_GHIDRA_VERSION}

RUN echo -e "Building versions:\n\
	RZ_PIPE_PY_VERSION=${RZ_PIPE_PY_VERSION}\
	RZ_GHIDRA_VERSION=${RZ_GHIDRA_VERSION}"

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
	ninja-build \
	cmake \
	gcc \
	cpp \
	g++ \
	git \
	make \
	pkg-config \
	libc-dev-bin libc6-dev linux-libc-dev \
	python3-pip \
	python3-setuptools \
	python3-wheel \
	${with_arm64_as:+binutils-aarch64-linux-gnu} \
	${with_arm32_as:+binutils-arm-linux-gnueabi} \
	${with_ppc_as:+binutils-powerpc64le-linux-gnu}

RUN pip3 install meson tomli

# Build rizin in a volume to minimize space used by build
COPY . /tmp/rizin/

WORKDIR /tmp/rizin
RUN meson setup --prefix=/usr -Dinstall_sigdb=true /tmp/build && \
	meson compile -C /tmp/build && \
	meson install --destdir /tmp/rizin-install -C /tmp/build

WORKDIR /tmp
RUN git clone -b "$RZ_PIPE_PY_VERSION" https://github.com/rizinorg/rz-pipe
RUN pip3 install --root=/tmp/rizin-install ./rz-pipe/python

WORKDIR /tmp
RUN git clone --recurse-submodules -b "$RZ_GHIDRA_VERSION" https://github.com/rizinorg/rz-ghidra
WORKDIR /tmp/rz-ghidra
RUN cmake -DCMAKE_PREFIX_PATH=/tmp/rizin-install/usr -DCMAKE_INSTALL_PREFIX=/usr -B build && cmake --build build && DESTDIR=/tmp/rizin-install cmake --build build --target install

FROM debian:10
ENV RZ_ARM64_AS=${with_arm64_as:+aarch64-linux-gnu-as}
ENV RZ_ARM32_AS=${with_arm32_as:+arm-linux-gnueabi-as}
ENV RZ_PPC_AS=${with_ppc_as:+powerpc64le-linux-gnu-as}

RUN useradd -m rizin
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git python3

USER rizin
WORKDIR /home/rizin
ENV HOME /home/rizin

COPY --from=0 /tmp/rizin-install/ /

CMD ["/bin/bash"]
