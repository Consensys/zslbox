####################################################
#  Base image with libzsl 
####################################################
FROM ubuntu:bionic as libzsl

# Install dependencies
RUN apt-get update && apt-get upgrade -q -y && \
	apt-get install -y --no-install-recommends golang-go build-essential g++ cmake make git ca-certificates libgmp-dev libc-dev libssl-dev libgmp3-dev libboost-all-dev && \
	rm -rf /var/lib/apt/lists/*

# Clone libsnark
RUN git clone https://github.com/scipr-lab/libsnark.git && \
	cd libsnark && \
	git reset --hard 3e92af18df7ea11588c9e59769e78dc7bc7ad4d9 && \
	git submodule init && \
	git submodule update

# Add libzsl source
COPY ./snark/libsnark/libzsl /libsnark/libzsl

# Build libsnark (+zsl)
WORKDIR "/libsnark"
RUN echo "add_subdirectory(libzsl)" >> /libsnark/CMakeLists.txt
RUN mkdir build && \
 	cd build && \
 	cmake -DCMAKE_CXX_FLAGS='-Wno-unused-variable -Wno-unused-parameter' -DMULTICORE=ON -DLOWMEM=OFF -DCURVE=ALT_BN128 -DWITH_SUPERCOP=OFF -DUSE_PT_COMPRESSION=OFF -DWITH_PROCPS=OFF .. && \
 	make && \
 	cp /libsnark/build/libzsl/libzsl.a /root/ && \
 	cp /libsnark/build/depends/libff/libff/libff.a /root/ && \
 	rm -rf /libsnark

# Generate gRPC certificate
# DO NOT USE IN PROD!
WORKDIR "/root/"
COPY ./gencert.sh /root/
RUN ./gencert.sh


####################################################
#  Building ZSLBox (depends on libzsl) 
####################################################
FROM libzsl as builder

ARG ZSLBOX_REPO=github.com/consensys/zslbox
ENV ZSLBOX_REPO=${ZSLBOX_REPO}

# Add zslbox source
RUN mkdir -p /root/go/src/$ZSLBOX_REPO
COPY . /root/go/src/$ZSLBOX_REPO

# Copy libzsl
COPY --from=libzsl /root/libzsl.a /root/go/src/$ZSLBOX_REPO/snark/
COPY --from=libzsl /root/libff.a /root/go/src/$ZSLBOX_REPO/snark/

# Build ZSLBox
WORKDIR "/root/go/src/${ZSLBOX_REPO}"

RUN go vet -v ./...
RUN go build

# Copy binary
RUN mv /root/go/src/$ZSLBOX_REPO/zslbox /root/

####################################################
#  Final stripped target
####################################################
FROM ubuntu:bionic
MAINTAINER gautam.botrel@consensys.net
COPY --from=builder /root /root
COPY --from=builder /usr/lib/x86_64-linux-gnu/libgomp.so.1 /usr/lib/
COPY --from=builder /root/server.crt /root
COPY --from=builder /root/server.key /root
WORKDIR "/root/"
ENTRYPOINT ["/root/zslbox"]