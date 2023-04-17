FROM python:3.11 as builder

RUN pip install poetry
ADD . /src
WORKDIR /src
RUN poetry build


FROM docker.io/jschlyter/nsd

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install bind9-dnsutils
RUN apt-get -y install git pipx
RUN apt-get -y install lighttpd curl

ENV PATH $PATH:/root/.local/bin

COPY --from=builder /src/dist/*.whl /tmp
RUN pipx install /tmp/*.whl
RUN rm -f /tmp/*.whl

ADD entrypoint.sh /
