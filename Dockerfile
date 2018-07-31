##########################
#  First stage, building #
##########################
FROM ubuntu:bionic as builder
MAINTAINER gautam.botrel@consensys.net

ARG ZSLBOX_REPO=github.com/consensys/zslbox
ENV ZSLBOX_REPO=${ZSLBOX_REPO}

# Install dependencies
RUN apt-get update && apt-get upgrade -q -y && \
	apt-get install -y --no-install-recommends golang-go build-essential g++ cmake make git ca-certificates libgmp-dev libc-dev libssl-dev libgmp3-dev libboost-all-dev && \
	rm -rf /var/lib/apt/lists/*

# Clone libsnark
RUN git clone https://github.com/scipr-lab/libsnark.git && cd libsnark && git submodule init && git submodule update

# Add libzsl source
COPY ./snark/libsnark/libzsl /libsnark/libzsl

# Add zslbox source
RUN mkdir -p /root/go/src/$ZSLBOX_REPO
COPY . /root/go/src/$ZSLBOX_REPO

# Build libsnark (+zsl)
WORKDIR "/libsnark"
RUN echo "add_subdirectory(libzsl)" >> /libsnark/CMakeLists.txt
RUN mkdir build && \
 	cd build && \
 	cmake -DCMAKE_CXX_FLAGS='-Wno-unused-variable -Wno-unused-parameter' -DMULTICORE=ON -DLOWMEM=ON -DCURVE=ALT_BN128 -DWITH_SUPERCOP=OFF -DUSE_PT_COMPRESSION=OFF -DWITH_PROCPS=OFF .. && \
 	make && \
 	cp /libsnark/build/libzsl/libzsl.a  /root/go/src/$ZSLBOX_REPO/snark/ && \
 	cp /libsnark/build/depends/libff/libff/libff.a  /root/go/src/$ZSLBOX_REPO/snark/


# Build ZSLBox
WORKDIR "/root/go/src/${ZSLBOX_REPO}"
RUN go build

# Keep zslbox binary only
WORKDIR "/root/"
COPY ./gencert.sh /root/
RUN ./gencert.sh && \
 	mv /root/go/src/$ZSLBOX_REPO/zslbox . && \
	rm -rf /libsnark
	# apt-get remove --purge git golang-go cmake make build-essential


##########################
#  Second stage binaries #
##########################
FROM ubuntu:bionic
MAINTAINER gautam.botrel@consensys.net
COPY --from=builder /root /root
RUN apt-get update && apt-get upgrade -q -y && \
	apt-get install -y --no-install-recommends libgomp1 && \
	rm -rf /var/lib/apt/lists/*
WORKDIR "/root/"
ENTRYPOINT ["/root/zslbox"]