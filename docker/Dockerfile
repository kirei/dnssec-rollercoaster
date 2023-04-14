FROM docker.io/jschlyter/nsd

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install bind9-dnsutils
RUN apt-get -y install git pipx
RUN apt-get -y install lighttpd curl

ENV PATH $PATH:/root/.local/bin

ADD rollercoaster-*.whl /tmp
RUN pipx install /tmp/rollercoaster-*.whl
RUN rm -f /tmp/rollercoaster-*.whl

ADD entrypoint.sh /
