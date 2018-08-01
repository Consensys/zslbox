######################################################
#  Used by CI, please use Dockerfile for full build  #
######################################################
FROM pegasystech/libzsl:latest 
MAINTAINER gautam.botrel@consensys.net

ARG ZSLBOX_REPO=github.com/consensys/zslbox
ENV ZSLBOX_REPO=${ZSLBOX_REPO}

# Add zslbox source
RUN mkdir -p /root/go/src/$ZSLBOX_REPO
COPY . /root/go/src/$ZSLBOX_REPO

# Copy libzsl to enable go vet to run
RUN cp /root/libzsl.a  /root/go/src/$ZSLBOX_REPO/snark/ && \
 	cp /root/libff.a  /root/go/src/$ZSLBOX_REPO/snark/


WORKDIR "/root/go/src/${ZSLBOX_REPO}"
