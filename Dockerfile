FROM ubuntu:xenial

RUN apt-get -y update && \
    apt-get install -y git bash curl wget python python-pip

ADD dist /tmp/dist/

RUN cd /tmp/dist && \
    tar -xvf *.tar.gz --strip 1 && \
    cd /tmp/dist && \
    python setup.py install && \
    cd / && rm -rf /tmp/dist

